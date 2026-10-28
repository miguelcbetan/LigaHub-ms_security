package com.uc.ms_security;

import com.uc.ms_security.entity.TwoFactorChallenge;
import com.uc.ms_security.entity.User;
import com.uc.ms_security.exception.ApplicationException;
import com.uc.ms_security.exception.ErrorCase;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.test.web.servlet.MvcResult;

import java.time.LocalDateTime;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

/** Escenarios 1-7 de la HU: acceso tradicional y segundo factor. */
class PasswordAndTwoFactorLoginTest extends AbstractAuthTest {

    @Test
    void validCredentialsCreateSession() throws Exception { // 1, 19, 20
        User user = localUser("ana@liga.test", true, false);

        MvcResult result = login("ana@liga.test", PASSWORD);

        assertThat(result.getResponse().getStatus()).isEqualTo(200);
        assertThat(field(result, "$.tokenType")).isEqualTo("Bearer");
        assertThat(field(result, "$.twoFactorRequired")).isEqualTo("false");
        assertThat(field(result, "$.expiresAt")).isNotBlank();

        var sessions = sessionRepository.findAllByUserId(user.getId());
        assertThat(sessions).hasSize(1);
        assertThat(sessions.get(0).getToken()).isNotBlank();
        assertThat(sessions.get(0).getExpiration()).isAfter(LocalDateTime.now());
        verify(emailClient, never()).sendTwoFactorCode(anyString(), anyString(), anyInt());
    }

    @Test
    void wrongPasswordIsRejectedWithoutSession() throws Exception { // 2
        User user = localUser("ana@liga.test", true, false);

        MvcResult result = login("ana@liga.test", "Otra123!clave");

        assertThat(result.getResponse().getStatus()).isEqualTo(401);
        assertThat(sessionRepository.findAllByUserId(user.getId())).isEmpty();
    }

    @Test
    void unknownEmailGetsSameAnswerAsWrongPassword() throws Exception { // 3
        localUser("ana@liga.test", true, false);

        MvcResult unknown = login("nadie@liga.test", PASSWORD);
        MvcResult wrong = login("ana@liga.test", "Otra123!clave");

        assertThat(unknown.getResponse().getStatus()).isEqualTo(401);
        assertThat(field(unknown, "$.message")).isEqualTo(field(wrong, "$.message"));
    }

    @Test
    void disabledAccountCannotAuthenticate() throws Exception { // 4
        User user = localUser("baja@liga.test", false, false);

        MvcResult result = login("baja@liga.test", PASSWORD);

        assertThat(result.getResponse().getStatus()).isEqualTo(403);
        assertThat(sessionRepository.findAllByUserId(user.getId())).isEmpty();
    }

    @Test
    void twoFactorPendingGivesNoSessionAndNoAccess() throws Exception { // 5
        User user = localUser("dos@liga.test", true, true);

        MvcResult result = login("dos@liga.test", PASSWORD);

        assertThat(result.getResponse().getStatus()).isEqualTo(200);
        assertThat(field(result, "$.twoFactorRequired")).isEqualTo("true");
        assertThat(field(result, "$.accessToken")).isNull();
        String challengeId = field(result, "$.challengeId");
        assertThat(challengeId).isNotBlank();
        assertThat(sessionRepository.findAllByUserId(user.getId())).isEmpty();

        // Ni sin token, ni usando el desafío como si fuera un token.
        assertThat(getWith("/api/auth/me", null).getResponse().getStatus()).isEqualTo(401);
        assertThat(getWith("/api/auth/me", challengeId).getResponse().getStatus()).isEqualTo(401);

        // El código viajó solo por correo y no consta en la respuesta ni en la BD.
        ArgumentCaptor<String> code = ArgumentCaptor.forClass(String.class);
        verify(emailClient).sendTwoFactorCode(eq("dos@liga.test"), code.capture(), eq(5));
        assertThat(code.getValue()).matches("\\d{6}");
        assertThat(result.getResponse().getContentAsString()).doesNotContain(code.getValue());
        assertThat(challengeRepository.findById(challengeId).orElseThrow().getCodeHash())
                .doesNotContain(code.getValue());
    }

    @Test
    void correctCodeCompletesAuthentication() throws Exception { // 6
        User user = localUser("dos@liga.test", true, true);
        MvcResult first = login("dos@liga.test", PASSWORD);
        String challengeId = field(first, "$.challengeId");
        String code = sentCode();

        MvcResult result = verify2fa(challengeId, code);

        assertThat(result.getResponse().getStatus()).isEqualTo(200);
        String token = field(result, "$.accessToken");
        assertThat(token).isNotBlank();
        assertThat(sessionRepository.findAllByUserId(user.getId())).hasSize(1);
        assertThat(getWith("/api/auth/me", token).getResponse().getStatus()).isEqualTo(200);

        // Un código solo sirve una vez.
        assertThat(verify2fa(challengeId, code).getResponse().getStatus()).isEqualTo(401);
    }

    @Test
    void wrongCodeIsRejectedAndAttemptsAreLimited() throws Exception { // 7
        localUser("dos@liga.test", true, true);
        String challengeId = field(login("dos@liga.test", PASSWORD), "$.challengeId");
        String code = sentCode();
        String wrong = code.equals("000000") ? "111111" : "000000";

        for (int i = 0; i < 3; i++) { // security.two-factor.max-attempts=3 en pruebas
            assertThat(verify2fa(challengeId, wrong).getResponse().getStatus()).isEqualTo(401);
        }

        // Agotados los intentos ya no sirve ni el código correcto.
        assertThat(verify2fa(challengeId, code).getResponse().getStatus()).isEqualTo(401);
        assertThat(sessionRepository.findAll()).isEmpty();
    }

    @Test
    void expiredCodeIsRejected() throws Exception { // 7
        localUser("dos@liga.test", true, true);
        String challengeId = field(login("dos@liga.test", PASSWORD), "$.challengeId");
        String code = sentCode();

        TwoFactorChallenge challenge = challengeRepository.findById(challengeId).orElseThrow();
        challenge.setExpiresAt(LocalDateTime.now().minusSeconds(1));
        challengeRepository.save(challenge);

        assertThat(verify2fa(challengeId, code).getResponse().getStatus()).isEqualTo(401);
        assertThat(sessionRepository.findAll()).isEmpty();
    }

    @Test
    void newLoginInvalidatesPreviousChallenge() throws Exception {
        localUser("dos@liga.test", true, true);
        String firstId = field(login("dos@liga.test", PASSWORD), "$.challengeId");
        String firstCode = sentCode();
        login("dos@liga.test", PASSWORD);

        assertThat(verify2fa(firstId, firstCode).getResponse().getStatus()).isEqualTo(401);
    }

    @Test
    void mailFailureLeavesNoUsableChallenge() throws Exception {
        localUser("dos@liga.test", true, true);
        doThrow(new ApplicationException(ErrorCase.SERVICE_UNAVAILABLE, "sin correo"))
                .when(emailClient).sendTwoFactorCode(anyString(), anyString(), anyInt());

        MvcResult result = login("dos@liga.test", PASSWORD);

        assertThat(result.getResponse().getStatus()).isEqualTo(503);
        assertThat(challengeRepository.findAll()).isEmpty();
        assertThat(sessionRepository.findAll()).isEmpty();
    }

    @Test
    void twoFactorCanBeToggledByLocalUser() throws Exception {
        localUser("ana@liga.test", true, false);
        String token = loginToken("ana@liga.test");

        var put = org.springframework.test.web.servlet.request.MockMvcRequestBuilders
                .put("/api/auth/2fa-settings")
                .header("Authorization", "Bearer " + token)
                .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                .content("{\"enabled\":true}");
        assertThat(mockMvc.perform(put).andReturn().getResponse().getStatus()).isEqualTo(204);

        assertThat(field(login("ana@liga.test", PASSWORD), "$.twoFactorRequired"))
                .isEqualTo("true");
    }

    private String sentCode() {
        ArgumentCaptor<String> code = ArgumentCaptor.forClass(String.class);
        verify(emailClient, org.mockito.Mockito.atLeastOnce())
                .sendTwoFactorCode(anyString(), code.capture(), anyInt());
        return code.getValue();
    }
}
