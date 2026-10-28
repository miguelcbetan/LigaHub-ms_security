package com.uc.ms_security.service;

import com.uc.ms_security.exception.ApplicationException;
import com.uc.ms_security.exception.ErrorCase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

import java.net.http.HttpClient;
import java.time.Duration;
import java.util.Map;

@Component
public class HttpEmailClient implements EmailClient {

    private static final Logger log = LoggerFactory.getLogger(HttpEmailClient.class);

    private final RestClient restClient;
    private final String apiKey;

    public HttpEmailClient(
            @Value("${email-service.url:http://127.0.0.1:5000}") String baseUrl,
            @Value("${email-service.api-key:}") String apiKey) {

        JdkClientHttpRequestFactory factory = new JdkClientHttpRequestFactory(
                HttpClient.newBuilder()
                        .connectTimeout(Duration.ofSeconds(3))
                        .build());
        factory.setReadTimeout(Duration.ofSeconds(10));

        this.restClient = RestClient.builder()
                .baseUrl(baseUrl)
                .requestFactory(factory)
                .build();
        this.apiKey = apiKey;
    }

    @Override
    public void sendTwoFactorCode(String email, String code, int expiresMinutes) {
        if (apiKey == null || apiKey.isBlank()) {
            log.error("email-service.api-key no está configurada; no se envía el código 2FA");
            throw unavailable();
        }

        try {
            restClient.post()
                    .uri("/api/2fa/send")
                    .header("X-Service-Key", apiKey)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(Map.of(
                            "email", email,
                            "code", code,
                            "expires_minutes", expiresMinutes))
                    .retrieve()
                    .toBodilessEntity();
        } catch (RestClientException e) {
            // Solo el tipo de fallo: el mensaje podría incluir datos de la petición.
            log.warn("El servicio de correo rechazó o no atendió el envío 2FA ({})",
                    e.getClass().getSimpleName());
            throw unavailable();
        }
    }

    private ApplicationException unavailable() {
        return new ApplicationException(
                ErrorCase.SERVICE_UNAVAILABLE,
                "No fue posible enviar el código de verificación. Inténtalo más tarde"
        );
    }
}
