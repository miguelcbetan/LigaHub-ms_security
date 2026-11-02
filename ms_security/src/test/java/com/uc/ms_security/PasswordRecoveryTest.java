package com.uc.ms_security;

import com.uc.ms_security.entity.AuthMethod;
import com.uc.ms_security.entity.PasswordResetToken;
import com.uc.ms_security.entity.User;
import org.junit.jupiter.api.Test;
import org.springframework.test.web.servlet.MvcResult;

import java.net.URI;
import java.time.LocalDateTime;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

class PasswordRecoveryTest extends AbstractAuthTest {

    private MvcResult requestRecovery(String email) throws Exception {
        return json(post("/api/auth/password-recovery"),
                "{\"email\":\"%s\"}".formatted(email));
    }

    private MvcResult reset(String token, String password) throws Exception {
        return json(post("/api/auth/password-reset"),
                "{\"token\":\"%s\",\"password\":\"%s\"}"
                        .formatted(token, password));
    }

    private String tokenFromEmail(String email) throws Exception {
        var link = org.mockito.ArgumentCaptor.forClass(String.class);
        verify(emailClient).sendPasswordReset(eq(email), link.capture(), eq(15));
        return tokenFromLink(link.getValue());
    }

    private String tokenFromLink(String link) {
        URI uri = URI.create(link);
        assertThat(uri.getPath()).isEqualTo("/recuperar");
        assertThat(uri.getRawQuery()).startsWith("token=");
        return uri.getRawQuery().substring("token=".length());
    }

    private User oauthUser(String email) {
        User user = new User();
        user.setName("Cuenta externa");
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode("secreto-interno"));
        user.setAuthMethod(AuthMethod.OAUTH);
        return userRepository.save(user);
    }

    @Test
    void recoveryRequestCreatesOnlyHashedTokenAndUsesGenericResponse() throws Exception {
        String email = "hash-token@liga.test";
        localUser(email, true, false);

        MvcResult result = requestRecovery(email);

        assertThat(result.getResponse().getStatus()).isEqualTo(202);
        assertThat(field(result, "$.message"))
                .isEqualTo(field(requestRecovery("inexistente@liga.test"), "$.message"));
        assertThat(passwordResetTokenRepository.count()).isEqualTo(1);

        String rawToken = tokenFromEmail(email);
        PasswordResetToken saved = passwordResetTokenRepository.findAll().get(0);
        assertThat(saved.getTokenHash()).hasSize(64).isNotEqualTo(rawToken);
        assertThat(saved.getExpiresAt()).isAfter(LocalDateTime.now());
    }

    @Test
    void resetChangesPasswordConsumesTokenAndRevokesExistingSessions() throws Exception {
        String email = "revoke-sessions@liga.test";
        localUser(email, true, false);
        String oldAccessToken = loginToken(email);
        assertThat(sessionRepository.count()).isEqualTo(1);

        assertThat(requestRecovery(email).getResponse().getStatus()).isEqualTo(202);
        String resetToken = tokenFromEmail(email);

        MvcResult result = reset(resetToken, "Nueva123!");

        assertThat(result.getResponse().getStatus()).isEqualTo(204);
        assertThat(sessionRepository.count()).isZero();
        assertThat(getWith("/api/auth/me", oldAccessToken)
                .getResponse().getStatus()).isEqualTo(401);
        assertThat(login(email, "Nueva123!").getResponse().getStatus()).isEqualTo(200);
        assertThat(login(email, PASSWORD).getResponse().getStatus()).isEqualTo(401);
        assertThat(reset(resetToken, "Otra123!").getResponse().getStatus()).isEqualTo(400);
    }

    @Test
    void expiredTokenIsRejectedWithoutChangingPassword() throws Exception {
        String email = "expired-token@liga.test";
        localUser(email, true, false);
        requestRecovery(email);
        String resetToken = tokenFromEmail(email);

        PasswordResetToken saved = passwordResetTokenRepository.findAll().get(0);
        saved.setExpiresAt(LocalDateTime.now().minusMinutes(1));
        passwordResetTokenRepository.save(saved);

        assertThat(reset(resetToken, "Nueva123!").getResponse().getStatus()).isEqualTo(400);
        assertThat(login(email, PASSWORD).getResponse().getStatus()).isEqualTo(200);
    }

    @Test
    void recoveryDoesNotSendEmailForOauthOrUnknownAccounts() throws Exception {
        oauthUser("oauth@liga.test");

        MvcResult oauthResult = requestRecovery("oauth@liga.test");
        MvcResult unknownResult = requestRecovery("desconocido@liga.test");

        assertThat(oauthResult.getResponse().getStatus()).isEqualTo(202);
        assertThat(unknownResult.getResponse().getStatus()).isEqualTo(202);
        assertThat(field(oauthResult, "$.message"))
                .isEqualTo(field(unknownResult, "$.message"));
        assertThat(passwordResetTokenRepository.count()).isZero();
        verify(emailClient, never()).sendPasswordReset(
                anyString(), anyString(), anyInt());
        assertThat(reset("A".repeat(43), "Nueva123!")
                .getResponse().getStatus()).isEqualTo(400);
    }

    @Test
    void weakNewPasswordIsRejectedByValidation() throws Exception {
        String email = "weak-password@liga.test";
        localUser(email, true, false);
        requestRecovery(email);
        String resetToken = tokenFromEmail(email);

        MvcResult result = reset(resetToken, "weakpass");

        assertThat(result.getResponse().getStatus()).isEqualTo(400);
        assertThat(passwordResetTokenRepository.findAll().get(0).isConsumed())
                .isFalse();
    }

    @Test
    void newRecoveryRequestInvalidatesEarlierToken() throws Exception {
        String email = "replace-token@liga.test";
        localUser(email, true, false);

        requestRecovery(email);
        requestRecovery(email);
        var links = org.mockito.ArgumentCaptor.forClass(String.class);
        verify(emailClient, times(2))
                .sendPasswordReset(eq(email), links.capture(), eq(15));
        String firstToken = tokenFromLink(links.getAllValues().get(0));
        String secondToken = tokenFromLink(links.getAllValues().get(1));

        assertThat(passwordResetTokenRepository.findAll())
                .filteredOn(PasswordResetToken::isConsumed)
                .hasSize(1);
        assertThat(reset(firstToken, "Nueva123!").getResponse().getStatus()).isEqualTo(400);
        assertThat(reset(secondToken, "Nueva123!").getResponse().getStatus()).isEqualTo(204);
    }
}
