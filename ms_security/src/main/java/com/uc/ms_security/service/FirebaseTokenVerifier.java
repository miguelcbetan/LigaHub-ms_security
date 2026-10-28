package com.uc.ms_security.service;

/** Verifica el ID token de Firebase y devuelve la identidad que contiene. */
public interface FirebaseTokenVerifier {

    /**
     * @throws com.uc.ms_security.exception.ApplicationException UNAUTHORIZED
     *         si el token no es auténtico, SERVICE_UNAVAILABLE si OAuth no
     *         está configurado o no se pudieron obtener las claves públicas
     */
    FirebaseIdentity verify(String idToken);

    /**
     * @param uid           identificador estable en Firebase ({@code sub})
     * @param provider      {@code google.com}, {@code github.com} o {@code microsoft.com}
     * @param email         puede ser null si el proveedor no lo entrega
     * @param emailVerified estado de verificación informado por el proveedor
     */
    record FirebaseIdentity(
            String uid,
            String provider,
            String email,
            boolean emailVerified,
            String name) {
    }
}
