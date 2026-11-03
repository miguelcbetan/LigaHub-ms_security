package com.uc.ms_security.service;

import com.uc.ms_security.dto.auth.AuthResponseDTO;
import com.uc.ms_security.entity.Session;
import com.uc.ms_security.entity.User;
import com.uc.ms_security.repository.SessionRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.time.ZoneId;

/**
 * Sesión interna tras una autenticación completa (contraseña, contraseña +
 * segundo factor u OAuth). El jti del JWT se guarda en {@code sessions}; sin
 * esa fila el token deja de ser válido (ver ActiveSessionValidator).
 */
@Service
@RequiredArgsConstructor
public class AuthSessionService {

    private final JwtService jwtService;
    private final SessionRepository sessionRepository;

    @Transactional
    public AuthResponseDTO start(User user) {
        JwtService.IssuedToken issued = jwtService.generateToken(user);

        Session session = new Session();
        session.setToken(issued.jti());
        session.setExpiration(LocalDateTime.ofInstant(
                issued.expiresAt(), ZoneId.systemDefault()));
        session.setUser(user);
        sessionRepository.save(session);

        return AuthResponseDTO.authenticated(
                issued.token(), issued.expiresAt());
    }

    /** Cierre de sesión: el token deja de autorizar cualquier operación. */
    @Transactional
    public void revoke(String jti, Long userId) {
        sessionRepository.deleteByTokenAndUserId(jti, userId);
    }

    @Scheduled(fixedDelayString = "PT1H", initialDelayString = "PT10M")
    @Transactional
    public void purgeExpired() {
        sessionRepository.deleteExpired(LocalDateTime.now());
    }
}
