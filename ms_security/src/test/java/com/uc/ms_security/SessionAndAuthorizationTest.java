package com.uc.ms_security;

import com.uc.ms_security.entity.Role;
import com.uc.ms_security.entity.Session;
import com.uc.ms_security.entity.User;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.test.web.servlet.MvcResult;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/** Escenarios 19-26 de la HU: sesión interna, revocación y autorización. */
class SessionAndAuthorizationTest extends AbstractAuthTest {

    @Autowired private JwtEncoder jwtEncoder;

    @Test
    void sessionHasIdentifierAndExpirationAndAuthorizesMe() throws Exception { // 19, 20
        User user = localUser("ana@liga.test", true, false);
        String token = loginToken("ana@liga.test");

        Session session = sessionRepository.findAllByUserId(user.getId()).get(0);
        assertThat(session.getToken()).isNotBlank();
        assertThat(session.getExpiration()).isAfter(LocalDateTime.now().plusMinutes(10));
        assertThat(session.getUser().getId()).isEqualTo(user.getId());

        MvcResult me = getWith("/api/auth/me", token);
        assertThat(me.getResponse().getStatus()).isEqualTo(200);
        assertThat(field(me, "$.email")).isEqualTo("ana@liga.test");
        assertThat(field(me, "$.authMethod")).isEqualTo("LOCAL");
    }

    @Test
    void expiredSessionIsRejectedByBackend() throws Exception { // 21
        User user = localUser("ana@liga.test", true, false);
        String token = loginToken("ana@liga.test");

        Session session = sessionRepository.findAllByUserId(user.getId()).get(0);
        session.setExpiration(LocalDateTime.now().minusSeconds(1));
        sessionRepository.save(session);

        assertThat(getWith("/api/auth/me", token).getResponse().getStatus()).isEqualTo(401);
    }

    @Test
    void expiredJwtIsRejected() throws Exception { // 21
        User user = localUser("ana@liga.test", true, false);
        String jti = UUID.randomUUID().toString();
        Session session = new Session();
        session.setToken(jti);
        session.setExpiration(LocalDateTime.now().plusMinutes(10)); // la fila sigue vigente
        session.setUser(user);
        sessionRepository.save(session);

        String token = jwtEncoder.encode(JwtEncoderParameters.from(
                JwsHeader.with(MacAlgorithm.HS256).build(),
                JwtClaimsSet.builder()
                        .issuer("ms-security")
                        .subject(user.getId().toString())
                        .id(jti)
                        .issuedAt(Instant.now().minusSeconds(3600))
                        .expiresAt(Instant.now().minusSeconds(1800))
                        .build())).getTokenValue();

        assertThat(getWith("/api/auth/me", token).getResponse().getStatus()).isEqualTo(401);
    }

    @Test
    void validSignatureWithoutRegisteredSessionIsRejected() throws Exception { // 22 (variante)
        User user = localUser("ana@liga.test", true, false);

        String token = jwtEncoder.encode(JwtEncoderParameters.from(
                JwsHeader.with(MacAlgorithm.HS256).build(),
                JwtClaimsSet.builder()
                        .issuer("ms-security")
                        .subject(user.getId().toString())
                        .id(UUID.randomUUID().toString())
                        .issuedAt(Instant.now())
                        .expiresAt(Instant.now().plusSeconds(600))
                        .build())).getTokenValue();

        assertThat(getWith("/api/auth/me", token).getResponse().getStatus()).isEqualTo(401);
    }

    @Test
    void logoutRevokesTokenAndAllowsNewLogin() throws Exception { // 22, 23
        User user = localUser("ana@liga.test", true, false);
        String token = loginToken("ana@liga.test");
        assertThat(getWith("/api/auth/me", token).getResponse().getStatus()).isEqualTo(200);

        assertThat(postWith("/api/auth/logout", token).getResponse().getStatus()).isEqualTo(204);

        assertThat(getWith("/api/auth/me", token).getResponse().getStatus()).isEqualTo(401);
        assertThat(sessionRepository.findAllByUserId(user.getId())).isEmpty();

        String second = loginToken("ana@liga.test");
        assertThat(second).isNotEqualTo(token);
        assertThat(getWith("/api/auth/me", second).getResponse().getStatus()).isEqualTo(200);
        assertThat(getWith("/api/auth/me", token).getResponse().getStatus()).isEqualTo(401);
    }

    @Test
    void logoutOnlyRevokesTheCurrentSession() throws Exception {
        localUser("ana@liga.test", true, false);
        String a = loginToken("ana@liga.test");
        String b = loginToken("ana@liga.test");

        postWith("/api/auth/logout", a);

        assertThat(getWith("/api/auth/me", a).getResponse().getStatus()).isEqualTo(401);
        assertThat(getWith("/api/auth/me", b).getResponse().getStatus()).isEqualTo(200);
    }

    @Test
    void protectedOperationsRequireValidSession() throws Exception { // 24
        assertThat(getWith("/api/users", null).getResponse().getStatus()).isEqualTo(401);
        assertThat(getWith("/api/users", "no.es.un.jwt").getResponse().getStatus()).isEqualTo(401);
        assertThat(postWith("/api/auth/logout", "no.es.un.jwt").getResponse().getStatus())
                .isEqualTo(401);
    }

    @Test
    void rolesAndPermissionsAreEnforcedByBackend() throws Exception { // 25, 26
        User reader = localUser("lector@liga.test", true, false);
        User nobody = localUser("nadie@liga.test", true, false);

        Role readers = role("LECTOR");
        grant(readers, "GET", "/api/roles");
        assign(reader, readers);
        assign(nobody, role(INITIAL_ROLE));

        String readerToken = loginToken("lector@liga.test");
        String nobodyToken = loginToken("nadie@liga.test");

        assertThat(getWith("/api/roles", readerToken).getResponse().getStatus()).isEqualTo(200);
        assertThat(getWith("/api/roles", nobodyToken).getResponse().getStatus()).isEqualTo(403);

        // Tener un permiso GET no habilita otros métodos ni otras rutas.
        MvcResult create = mockMvc.perform(post("/api/roles")
                .header("Authorization", "Bearer " + readerToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"name\":\"X\",\"description\":\"Y\"}")).andReturn();
        assertThat(create.getResponse().getStatus()).isEqualTo(403);
        assertThat(getWith("/api/permissions", readerToken).getResponse().getStatus())
                .isEqualTo(403);

        // /me refleja los permisos efectivos derivados de los roles.
        MvcResult me = getWith("/api/auth/me", readerToken);
        List<String> roles = com.jayway.jsonpath.JsonPath.read(
                me.getResponse().getContentAsString(), "$.roles");
        assertThat(roles).containsExactly("LECTOR");
    }

    @Test
    void selfRegistrationDoesNotGrantPrivileges() throws Exception { // 25, 26
        role(INITIAL_ROLE);
        MvcResult registered = json(post("/api/users"),
                "{\"name\":\"Nueva\",\"email\":\"nueva@liga.test\",\"password\":\"%s\"}"
                        .formatted(PASSWORD));
        assertThat(registered.getResponse().getStatus()).isEqualTo(201);

        String token = loginToken("nueva@liga.test");

        assertThat(getWith("/api/users", token).getResponse().getStatus()).isEqualTo(403);
        assertThat(getWith("/api/roles", token).getResponse().getStatus()).isEqualTo(403);
    }

    @Test
    void disablingTheUserInvalidatesItsLiveToken() throws Exception {
        User user = localUser("ana@liga.test", true, false);
        String token = loginToken("ana@liga.test");

        user.setActive(false);
        userRepository.save(user);

        assertThat(getWith("/api/auth/me", token).getResponse().getStatus()).isEqualTo(401);
    }
}
