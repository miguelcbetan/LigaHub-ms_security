package com.uc.ms_security.service;

/** Puerto hacia el microservicio de correo (emails_google). */
public interface EmailClient {

    /**
     * Envía el código del segundo factor. El servicio de correo solo entrega
     * el mensaje: no genera ni valida el código.
     *
     * @throws com.uc.ms_security.exception.ApplicationException con
     *         SERVICE_UNAVAILABLE si el correo no pudo enviarse
     */
    void sendTwoFactorCode(String email, String code, int expiresMinutes);
}
