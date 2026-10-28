package com.uc.ms_security.authorization;

import com.uc.ms_security.repository.SessionRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;

/**
 * Un JWT firmado no basta: debe corresponder a una sesión registrada, no
 * revocada ni expirada, de un usuario que siga habilitado. Se evalúa en el
 * backend en cada petición protegida (cierre de sesión = borrar la sesión).
 */
@Component
@RequiredArgsConstructor
public class ActiveSessionValidator implements OAuth2TokenValidator<Jwt> {

    private static final OAuth2Error INVALID_SESSION = new OAuth2Error(
            "invalid_token",
            "La sesión no es válida, fue revocada o expiró",
            null
    );

    private final SessionRepository sessionRepository;

    @Override
    public OAuth2TokenValidatorResult validate(Jwt jwt) {
        String jti = jwt.getId();
        Long userId = parseUserId(jwt.getSubject());

        if (jti == null || userId == null) {
            return OAuth2TokenValidatorResult.failure(INVALID_SESSION);
        }

        boolean active = sessionRepository.existsActive(
                jti, userId, LocalDateTime.now());

        return active
                ? OAuth2TokenValidatorResult.success()
                : OAuth2TokenValidatorResult.failure(INVALID_SESSION);
    }

    private Long parseUserId(String subject) {
        try {
            return Long.valueOf(subject);
        } catch (NumberFormatException | NullPointerException e) {
            return null;
        }
    }
}
