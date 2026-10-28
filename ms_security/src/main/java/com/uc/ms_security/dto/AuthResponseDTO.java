package com.uc.ms_security.dto;

import java.time.Instant;

/**
 * Resultado de una autenticación. O bien trae el token de sesión, o bien
 * indica que falta el segundo factor ({@code twoFactorRequired}) y entonces
 * solo trae el desafío; en ese caso no existe sesión alguna.
 */
public record AuthResponseDTO(
        String accessToken,
        String tokenType,
        Instant expiresAt,
        boolean twoFactorRequired,
        String challengeId) {

    public static AuthResponseDTO authenticated(
            String accessToken,
            Instant expiresAt) {
        return new AuthResponseDTO(
                accessToken, "Bearer", expiresAt, false, null);
    }

    public static AuthResponseDTO twoFactorPending(
            String challengeId,
            Instant expiresAt) {
        return new AuthResponseDTO(
                null, null, expiresAt, true, challengeId);
    }
}
