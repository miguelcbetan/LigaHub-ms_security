package com.uc.ms_security.service;

import com.uc.ms_security.exception.ApplicationException;
import com.uc.ms_security.exception.ErrorCase;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Límite de intentos por clave en ventana deslizante, en memoria. Suficiente
 * para una sola instancia; con varias instancias habría que moverlo a un
 * almacén compartido.
 */
@Component
public class RateLimiter {

    private static final int MAX_TRACKED_KEYS = 10_000;

    private final Map<String, Deque<Long>> hits = new ConcurrentHashMap<>();

    public void check(String key, int maxAttempts, Duration window) {
        long now = System.currentTimeMillis();
        long limit = now - window.toMillis();

        if (hits.size() > MAX_TRACKED_KEYS) {
            hits.values().removeIf(d -> isStale(d, limit));
        }

        Deque<Long> deque = hits.computeIfAbsent(key, k -> new ArrayDeque<>());

        synchronized (deque) {
            while (!deque.isEmpty() && deque.peekFirst() < limit) {
                deque.pollFirst();
            }
            if (deque.size() >= maxAttempts) {
                throw new ApplicationException(
                        ErrorCase.TOO_MANY_REQUESTS,
                        "Demasiados intentos. Espera unos minutos e inténtalo de nuevo"
                );
            }
            deque.addLast(now);
        }
    }

    public void reset(String key) {
        hits.remove(key);
    }

    private boolean isStale(Deque<Long> deque, long limit) {
        synchronized (deque) {
            return deque.isEmpty() || deque.peekLast() < limit;
        }
    }
}
