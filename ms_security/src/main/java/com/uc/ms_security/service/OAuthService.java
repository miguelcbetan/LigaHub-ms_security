package com.uc.ms_security.service;

import com.uc.ms_security.dto.AuthResponseDTO;
import com.uc.ms_security.entity.User;
import com.uc.ms_security.exception.ApplicationException;
import com.uc.ms_security.exception.ErrorCase;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;

import java.time.Duration;

/**
 * Inicio de sesión con Google, GitHub o Microsoft vía Firebase. La identidad
 * se comprueba en el backend con el ID token; el cliente nunca aporta datos
 * de identidad sin verificar. No pasa por el 2FA de la plataforma.
 */
@Service
@RequiredArgsConstructor
public class OAuthService {

    private final FirebaseTokenVerifier tokenVerifier;
    private final ExternalIdentityService identityService;
    private final AuthSessionService authSessionService;
    private final RateLimiter rateLimiter;

    public AuthResponseDTO login(String idToken, String clientIp) {
        rateLimiter.check("oauth|" + clientIp, 30, Duration.ofMinutes(10));

        FirebaseTokenVerifier.FirebaseIdentity identity =
                tokenVerifier.verify(idToken);

        User user;
        try {
            user = identityService.findOrCreate(identity);
        } catch (DataIntegrityViolationException race) {
            // Primer acceso simultáneo: la otra solicitud ya confirmó el alta
            // (restricciones únicas); se reevalúa y se reutiliza esa identidad.
            user = identityService.findOrCreate(identity);
        }

        if (!user.isActive()) {
            throw new ApplicationException(
                    ErrorCase.FORBIDDEN, "La cuenta está deshabilitada");
        }

        return authSessionService.start(user);
    }
}
