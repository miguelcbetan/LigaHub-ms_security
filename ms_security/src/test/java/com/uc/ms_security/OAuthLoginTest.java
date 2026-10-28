package com.uc.ms_security;

import com.uc.ms_security.entity.AuthMethod;
import com.uc.ms_security.entity.Role;
import com.uc.ms_security.entity.User;
import com.uc.ms_security.exception.ApplicationException;
import com.uc.ms_security.exception.ErrorCase;
import com.uc.ms_security.service.FirebaseTokenVerifier.FirebaseIdentity;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.test.web.servlet.MvcResult;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Escenarios 8-18 de la HU. La verificación criptográfica del ID token se
 * prueba en {@link FirebaseTokenVerifierTest}; aquí el verificador es un mock
 * porque no se dispone de credenciales reales de Firebase.
 */
class OAuthLoginTest extends AbstractAuthTest {

    private void tokenIs(String idToken, String provider, String uid,
                         String email, boolean verified) {
        when(firebaseVerifier.verify(idToken)).thenReturn(
                new FirebaseIdentity(uid, provider, email, verified, "Persona Externa"));
    }

    @ParameterizedTest // 8-13: Google, GitHub y Microsoft
    @ValueSource(strings = {"google.com", "github.com", "microsoft.com"})
    void firstAccessCreatesUserAndLaterAccessReusesIt(String provider) throws Exception {
        Role initial = role(INITIAL_ROLE);
        grant(initial, "GET", "/api/profile/me");
        tokenIs("tok", provider, "uid-1", "externo@liga.test", true);

        MvcResult first = oauth("tok");

        assertThat(first.getResponse().getStatus()).isEqualTo(200);
        assertThat(field(first, "$.twoFactorRequired")).isEqualTo("false");
        String firstToken = field(first, "$.accessToken");
        User created = userRepository.findByEmail("externo@liga.test").orElseThrow();
        assertThat(created.getAuthMethod()).isEqualTo(AuthMethod.OAUTH);
        assertThat(created.isActive()).isTrue();
        assertThat(externalIdentityRepository
                .findByProviderAndProviderUid(provider, "uid-1")).isPresent();
        assertThat(userRoleRepository.findAll()).hasSize(1);

        // Un administrador le añade un rol; en el siguiente acceso se conserva.
        assign(created, role("LECTOR"));

        MvcResult second = oauth("tok");
        String secondToken = field(second, "$.accessToken");

        assertThat(second.getResponse().getStatus()).isEqualTo(200);
        assertThat(secondToken).isNotEqualTo(firstToken);
        assertThat(userRepository.count()).isEqualTo(1);
        assertThat(externalIdentityRepository.count()).isEqualTo(1);
        assertThat(sessionRepository.count()).isEqualTo(2);

        MvcResult me = getWith("/api/auth/me", secondToken);
        List<String> roles = com.jayway.jsonpath.JsonPath.read(
                me.getResponse().getContentAsString(), "$.roles");
        assertThat(roles).containsExactlyInAnyOrder(INITIAL_ROLE, "LECTOR");
        assertThat(field(me, "$.authMethod")).isEqualTo("OAUTH");

        // OAuth no pasa por el 2FA propio y no cuenta con contraseña utilizable.
        verify(emailClient, never()).sendTwoFactorCode(anyString(), anyString(), anyInt());
        assertThat(login("externo@liga.test", PASSWORD).getResponse().getStatus())
                .isEqualTo(401);
    }

    @Test
    void oauthUserGetsInitialRoleOnly() throws Exception {
        role(INITIAL_ROLE);
        tokenIs("tok", "google.com", "uid-1", "externo@liga.test", true);

        String token = field(oauth("tok"), "$.accessToken");

        assertThat(getWith("/api/users", token).getResponse().getStatus()).isEqualTo(403);
        assertThat(getWith("/api/roles", token).getResponse().getStatus()).isEqualTo(403);
    }

    @Test
    void invalidProviderTokenIsRejected() throws Exception { // 14
        role(INITIAL_ROLE);
        when(firebaseVerifier.verify("malo")).thenThrow(
                new ApplicationException(ErrorCase.UNAUTHORIZED, "No se pudo verificar"));

        MvcResult result = oauth("malo");

        assertThat(result.getResponse().getStatus()).isEqualTo(401);
        assertThat(userRepository.count()).isZero();
        assertThat(sessionRepository.count()).isZero();
    }

    @Test
    void disabledInternalAccountIsRejected() throws Exception { // 15
        role(INITIAL_ROLE);
        tokenIs("tok", "github.com", "uid-1", "externo@liga.test", true);
        oauth("tok");
        User user = userRepository.findByEmail("externo@liga.test").orElseThrow();
        user.setActive(false);
        userRepository.save(user);
        long sessionsBefore = sessionRepository.count();

        MvcResult result = oauth("tok");

        assertThat(result.getResponse().getStatus()).isEqualTo(403);
        assertThat(sessionRepository.count()).isEqualTo(sessionsBefore);
    }

    @Test
    void emailOfLocalAccountIsRejectedWithoutLinking() throws Exception { // 16
        role(INITIAL_ROLE);
        localUser("ana@liga.test", true, false);
        tokenIs("tok", "google.com", "uid-1", "ana@liga.test", true);

        MvcResult result = oauth("tok");

        assertThat(result.getResponse().getStatus()).isEqualTo(409);
        assertThat(userRepository.count()).isEqualTo(1);
        assertThat(externalIdentityRepository.count()).isZero();
        assertThat(sessionRepository.count()).isZero();
    }

    @Test
    void sameEmailFromAnotherProviderIsNotLinkedAutomatically() throws Exception { // 16
        role(INITIAL_ROLE);
        tokenIs("g", "google.com", "uid-g", "externo@liga.test", true);
        tokenIs("h", "github.com", "uid-h", "externo@liga.test", true);

        assertThat(oauth("g").getResponse().getStatus()).isEqualTo(200);
        assertThat(oauth("h").getResponse().getStatus()).isEqualTo(409);
        assertThat(userRepository.count()).isEqualTo(1);
        assertThat(externalIdentityRepository.count()).isEqualTo(1);
    }

    @Test
    void concurrentFirstAccessesCreateOneUser() throws Exception { // 17
        role(INITIAL_ROLE);
        tokenIs("tok", "microsoft.com", "uid-1", "externo@liga.test", true);

        int threads = 6;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<Integer>> futures = new ArrayList<>();
        for (int i = 0; i < threads; i++) {
            Callable<Integer> call = () -> {
                start.await();
                return oauth("tok").getResponse().getStatus();
            };
            futures.add(pool.submit(call));
        }
        start.countDown();

        for (Future<Integer> f : futures) {
            assertThat(f.get()).isEqualTo(200);
        }
        pool.shutdown();

        assertThat(userRepository.count()).isEqualTo(1);
        assertThat(externalIdentityRepository.count()).isEqualTo(1);
        assertThat(userRoleRepository.count()).isEqualTo(1);
    }

    @Test
    void providerWithoutEmailOrUnverifiedEmailIsRejected() throws Exception { // 18
        role(INITIAL_ROLE);
        tokenIs("sin-correo", "github.com", "uid-1", null, true);
        tokenIs("sin-verificar", "microsoft.com", "uid-2", "otro@liga.test", false);

        assertThat(oauth("sin-correo").getResponse().getStatus()).isEqualTo(400);
        assertThat(oauth("sin-verificar").getResponse().getStatus()).isEqualTo(400);
        assertThat(userRepository.count()).isZero();
    }

    @Test
    void providerOutageOrMissingConfigurationIsReportedAsUnavailable() throws Exception { // 18
        when(firebaseVerifier.verify("tok")).thenThrow(new ApplicationException(
                ErrorCase.SERVICE_UNAVAILABLE, "no configurado"));

        assertThat(oauth("tok").getResponse().getStatus()).isEqualTo(503);
    }

    @Test
    void missingInitialRoleCreatesNoUser() throws Exception {
        tokenIs("tok", "google.com", "uid-1", "externo@liga.test", true);

        MvcResult result = oauth("tok");

        assertThat(result.getResponse().getStatus()).isEqualTo(404);
        assertThat(userRepository.count()).isZero();
        assertThat(externalIdentityRepository.count()).isZero();
    }

    @Test
    void oauthUsersCannotToggleTwoFactor() throws Exception {
        role(INITIAL_ROLE);
        tokenIs("tok", "google.com", "uid-1", "externo@liga.test", true);
        String token = field(oauth("tok"), "$.accessToken");

        var put = org.springframework.test.web.servlet.request.MockMvcRequestBuilders
                .put("/api/auth/2fa-settings")
                .header("Authorization", "Bearer " + token)
                .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                .content("{\"enabled\":true}");

        assertThat(mockMvc.perform(put).andReturn().getResponse().getStatus()).isEqualTo(400);
    }
}
