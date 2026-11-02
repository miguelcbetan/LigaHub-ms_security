package com.uc.ms_security;

import com.sun.net.httpserver.HttpServer;
import com.uc.ms_security.exception.ApplicationException;
import com.uc.ms_security.exception.ErrorCase;
import com.uc.ms_security.service.HttpEmailClient;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Contrato con emails_google: cabecera de servicio, cuerpo y errores. */
class HttpEmailClientTest {

    private HttpServer server;
    private final AtomicReference<String> body = new AtomicReference<>();
    private final AtomicReference<String> serviceKey = new AtomicReference<>();
    private final AtomicReference<String> path = new AtomicReference<>();
    private volatile int status = 200;

    @BeforeEach
    void start() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            path.set(exchange.getRequestURI().getPath());
            serviceKey.set(exchange.getRequestHeaders().getFirst("X-Service-Key"));
            body.set(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            byte[] response = "{}".getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(status, response.length);
            exchange.getResponseBody().write(response);
            exchange.close();
        });
        server.start();
    }

    @AfterEach
    void stop() {
        server.stop(0);
    }

    private String url() {
        return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    @Test
    void sendsCodeWithServiceKeyAndExpectedPayload() {
        new HttpEmailClient(url(), "clave-ficticia").sendTwoFactorCode(
                "ana@liga.test", "123456", 5);

        assertThat(path.get()).isEqualTo("/api/2fa/send");
        assertThat(serviceKey.get()).isEqualTo("clave-ficticia");
        assertThat(body.get())
                .contains("\"email\":\"ana@liga.test\"")
                .contains("\"code\":\"123456\"")
                .contains("\"expires_minutes\":5");
    }

    @Test
    void sendsPasswordResetLinkWithServiceKeyAndExpectedPayload() {
        new HttpEmailClient(url(), "clave-ficticia").sendPasswordReset(
                "ana@liga.test",
                "http://localhost:3000/recuperar?token=token-seguro",
                15);

        assertThat(path.get()).isEqualTo("/api/password-reset/send");
        assertThat(serviceKey.get()).isEqualTo("clave-ficticia");
        assertThat(body.get())
                .contains("\"email\":\"ana@liga.test\"")
                .contains("\"reset_url\":\"http://localhost:3000/recuperar?token=token-seguro\"")
                .contains("\"expires_minutes\":15");
    }

    @Test
    void providerErrorBecomesServiceUnavailableWithoutLeakingDetails() {
        status = 502;

        assertThatThrownBy(() -> new HttpEmailClient(url(), "clave-ficticia")
                .sendTwoFactorCode("ana@liga.test", "123456", 5))
                .isInstanceOfSatisfying(ApplicationException.class, e -> {
                    assertThat(e.getErrorCase()).isEqualTo(ErrorCase.SERVICE_UNAVAILABLE);
                    assertThat(e.getMessage()).doesNotContain("123456", "ana@liga.test");
                });
    }

    @Test
    void unauthorizedByMailServiceBecomesServiceUnavailable() {
        status = 401;

        assertThatThrownBy(() -> new HttpEmailClient(url(), "equivocada")
                .sendTwoFactorCode("ana@liga.test", "123456", 5))
                .isInstanceOfSatisfying(ApplicationException.class, e ->
                        assertThat(e.getErrorCase()).isEqualTo(ErrorCase.SERVICE_UNAVAILABLE));
    }

    @Test
    void unreachableServiceBecomesServiceUnavailable() {
        server.stop(0);

        assertThatThrownBy(() -> new HttpEmailClient(url(), "clave-ficticia")
                .sendTwoFactorCode("ana@liga.test", "123456", 5))
                .isInstanceOfSatisfying(ApplicationException.class, e ->
                        assertThat(e.getErrorCase()).isEqualTo(ErrorCase.SERVICE_UNAVAILABLE));
    }

    @Test
    void missingApiKeyDoesNotSendAnything() {
        assertThatThrownBy(() -> new HttpEmailClient(url(), "")
                .sendTwoFactorCode("ana@liga.test", "123456", 5))
                .isInstanceOf(ApplicationException.class);
        assertThat(body.get()).isNull();
    }

    @Test
    void missingApiKeyDoesNotSendPasswordReset() {
        assertThatThrownBy(() -> new HttpEmailClient(url(), "")
                .sendPasswordReset(
                        "ana@liga.test",
                        "http://localhost:3000/recuperar?token=token",
                        15))
                .isInstanceOf(ApplicationException.class);
        assertThat(body.get()).isNull();
    }
}
