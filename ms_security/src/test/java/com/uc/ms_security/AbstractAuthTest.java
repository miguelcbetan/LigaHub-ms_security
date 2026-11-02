package com.uc.ms_security;

import com.jayway.jsonpath.JsonPath;
import com.uc.ms_security.entity.AuthMethod;
import com.uc.ms_security.entity.Permission;
import com.uc.ms_security.entity.Role;
import com.uc.ms_security.entity.RolePermission;
import com.uc.ms_security.entity.User;
import com.uc.ms_security.entity.UserRole;
import com.uc.ms_security.repository.ExternalIdentityRepository;
import com.uc.ms_security.repository.PasswordResetTokenRepository;
import com.uc.ms_security.repository.PermissionRepository;
import com.uc.ms_security.repository.RolePermissionRepository;
import com.uc.ms_security.repository.RoleRepository;
import com.uc.ms_security.repository.SessionRepository;
import com.uc.ms_security.repository.TwoFactorChallengeRepository;
import com.uc.ms_security.repository.UserRepository;
import com.uc.ms_security.repository.UserRoleRepository;
import com.uc.ms_security.service.EmailClient;
import com.uc.ms_security.service.FirebaseTokenVerifier;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import java.util.concurrent.atomic.AtomicInteger;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * Base de las pruebas de integración de HU-SE-08. Usa H2 en memoria y
 * sustituye por mocks los dos límites externos (correo y Firebase), de modo
 * que no hace falta ninguna credencial real.
 */
@SpringBootTest
@AutoConfigureMockMvc
abstract class AbstractAuthTest {

    static final String PASSWORD = "Valid123!";
    static final String INITIAL_ROLE = "USUARIO INICIAL";

    private static final AtomicInteger IP_SEQ = new AtomicInteger();

    @Autowired protected MockMvc mockMvc;
    @Autowired protected UserRepository userRepository;
    @Autowired protected RoleRepository roleRepository;
    @Autowired protected UserRoleRepository userRoleRepository;
    @Autowired protected PermissionRepository permissionRepository;
    @Autowired protected RolePermissionRepository rolePermissionRepository;
    @Autowired protected SessionRepository sessionRepository;
    @Autowired protected ExternalIdentityRepository externalIdentityRepository;
    @Autowired protected PasswordResetTokenRepository passwordResetTokenRepository;
    @Autowired protected TwoFactorChallengeRepository challengeRepository;
    @Autowired protected PasswordEncoder passwordEncoder;

    @MockitoBean protected EmailClient emailClient;
    @MockitoBean protected FirebaseTokenVerifier firebaseVerifier;

    /** IP distinta por prueba para que el límite de intentos no se cruce. */
    protected String clientIp;

    @BeforeEach
    void cleanDatabase() {
        passwordResetTokenRepository.deleteAll();
        challengeRepository.deleteAll();
        sessionRepository.deleteAll();
        externalIdentityRepository.deleteAll();
        userRoleRepository.deleteAll();
        rolePermissionRepository.deleteAll();
        userRepository.deleteAll();
        roleRepository.deleteAll();
        permissionRepository.deleteAll();

        int n = IP_SEQ.incrementAndGet();
        clientIp = "10." + (n / 250) + "." + (n % 250) + ".7";
    }

    protected User localUser(String email, boolean active, boolean twoFactor) {
        User user = new User();
        user.setName("Usuario de prueba");
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(PASSWORD));
        user.setActive(active);
        user.setTwoFactorEnabled(twoFactor);
        user.setAuthMethod(AuthMethod.LOCAL);
        return userRepository.save(user);
    }

    protected Role role(String name) {
        return roleRepository.findByNameIgnoreCase(name).orElseGet(() -> {
            Role role = new Role();
            role.setName(name);
            role.setDescription("Rol de prueba " + name);
            return roleRepository.save(role);
        });
    }

    protected void assign(User user, Role role) {
        UserRole userRole = new UserRole();
        userRole.setUser(user);
        userRole.setRole(role);
        userRoleRepository.save(userRole);
    }

    protected void grant(Role role, String method, String url) {
        Permission permission = new Permission();
        permission.setMethod(method);
        permission.setUrl(url);
        permission.setModel("Prueba");
        permission = permissionRepository.save(permission);

        RolePermission rolePermission = new RolePermission();
        rolePermission.setRole(role);
        rolePermission.setPermission(permission);
        rolePermissionRepository.save(rolePermission);
    }

    protected MvcResult login(String email, String password) throws Exception {
        return json(post("/api/auth/login"),
                "{\"email\":\"%s\",\"password\":\"%s\"}".formatted(email, password));
    }

    protected MvcResult oauth(String idToken) throws Exception {
        return json(post("/api/auth/oauth"),
                "{\"idToken\":\"%s\"}".formatted(idToken));
    }

    protected MvcResult verify2fa(String challengeId, String code) throws Exception {
        return json(post("/api/auth/2fa/verify"),
                "{\"challengeId\":\"%s\",\"code\":\"%s\"}".formatted(challengeId, code));
    }

    protected MvcResult json(MockHttpServletRequestBuilder builder, String body)
            throws Exception {
        return mockMvc.perform(builder
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body)
                        .with(request -> {
                            request.setRemoteAddr(clientIp);
                            return request;
                        }))
                .andReturn();
    }

    protected MvcResult getWith(String path, String token) throws Exception {
        MockHttpServletRequestBuilder builder = get(path);
        if (token != null) {
            builder.header("Authorization", "Bearer " + token);
        }
        return mockMvc.perform(builder).andReturn();
    }

    protected MvcResult postWith(String path, String token) throws Exception {
        return mockMvc.perform(post(path)
                .header("Authorization", "Bearer " + token)).andReturn();
    }

    protected String field(MvcResult result, String jsonPath) throws Exception {
        Object value = JsonPath.read(
                result.getResponse().getContentAsString(), jsonPath);
        return value == null ? null : value.toString();
    }

    protected String loginToken(String email) throws Exception {
        MvcResult result = login(email, PASSWORD);
        if (result.getResponse().getStatus() != 200) {
            throw new AssertionError("Login falló: " + result.getResponse().getStatus());
        }
        return field(result, "$.accessToken");
    }
}
