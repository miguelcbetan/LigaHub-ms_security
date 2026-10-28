package com.uc.ms_security.service;

import com.uc.ms_security.exception.ApplicationException;
import com.uc.ms_security.exception.ErrorCase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Map;
import java.util.Set;

/**
 * Verificación de ID tokens de Firebase según la guía oficial: firma RS256
 * con las claves públicas de securetoken@system.gserviceaccount.com, y
 * {@code exp}, {@code iat}, {@code aud} (= project id), {@code iss}
 * (= https://securetoken.google.com/&lt;project id&gt;), {@code sub} y
 * {@code auth_time}. No hace falta ninguna credencial privada, solo el
 * identificador público del proyecto.
 */
@Component
public class NimbusFirebaseTokenVerifier implements FirebaseTokenVerifier {

    private static final Logger log =
            LoggerFactory.getLogger(NimbusFirebaseTokenVerifier.class);

    static final Set<String> ALLOWED_PROVIDERS =
            Set.of("google.com", "github.com", "microsoft.com");

    private final String projectId;
    private final String jwkSetUri;
    private volatile JwtDecoder decoder;

    @Autowired
    public NimbusFirebaseTokenVerifier(
            @Value("${firebase.project-id:}") String projectId,
            @Value("${firebase.jwk-set-uri:https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com}")
            String jwkSetUri) {
        this.projectId = projectId == null ? "" : projectId.trim();
        this.jwkSetUri = jwkSetUri;
    }

    /** Para pruebas: permite inyectar un decodificador con claves locales. */
    public NimbusFirebaseTokenVerifier(String projectId, JwtDecoder decoder) {
        this.projectId = projectId;
        this.jwkSetUri = null;
        this.decoder = decoder;
    }

    /** Validadores que aplica el decodificador real; reutilizables en pruebas. */
    public static OAuth2TokenValidator<Jwt> validators(String projectId) {
        long skew = 60;

        return new DelegatingOAuth2TokenValidator<>(
                new JwtTimestampValidator(),
                new JwtIssuerValidator("https://securetoken.google.com/" + projectId),
                new JwtClaimValidator<Object>("aud", aud ->
                        aud instanceof Iterable<?> list
                                ? containsProject(list, projectId)
                                : projectId.equals(aud)),
                new JwtClaimValidator<String>("sub", sub ->
                        sub != null && !sub.isBlank() && sub.length() <= 128),
                new JwtClaimValidator<Object>("auth_time", authTime ->
                        authTime instanceof Number n
                                && n.longValue() <= Instant.now().getEpochSecond() + skew)
        );
    }

    private static boolean containsProject(Iterable<?> audiences, String projectId) {
        for (Object a : audiences) {
            if (projectId.equals(a)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public FirebaseIdentity verify(String idToken) {
        if (projectId.isBlank()) {
            throw new ApplicationException(
                    ErrorCase.SERVICE_UNAVAILABLE,
                    "El acceso con proveedores externos no está configurado"
            );
        }

        Jwt jwt;
        try {
            jwt = decoder().decode(idToken);
        } catch (BadJwtException e) {
            log.warn("ID token de Firebase rechazado ({})", e.getClass().getSimpleName());
            throw invalidToken();
        } catch (JwtException e) {
            log.warn("No se pudo validar el ID token de Firebase ({})",
                    e.getClass().getSimpleName());
            throw new ApplicationException(
                    ErrorCase.SERVICE_UNAVAILABLE,
                    "No fue posible verificar la identidad. Inténtalo más tarde"
            );
        }

        Map<String, Object> firebase = jwt.getClaimAsMap("firebase");
        Object signInProvider = firebase == null ? null : firebase.get("sign_in_provider");

        if (!(signInProvider instanceof String provider)
                || !ALLOWED_PROVIDERS.contains(provider)) {
            log.warn("Proveedor de inicio de sesión no admitido en el ID token");
            throw invalidToken();
        }

        return new FirebaseIdentity(
                jwt.getSubject(),
                provider,
                jwt.getClaimAsString("email"),
                Boolean.TRUE.equals(jwt.getClaimAsBoolean("email_verified")),
                jwt.getClaimAsString("name")
        );
    }

    private JwtDecoder decoder() {
        JwtDecoder local = decoder;
        if (local == null) {
            synchronized (this) {
                local = decoder;
                if (local == null) {
                    NimbusJwtDecoder created = NimbusJwtDecoder
                            .withJwkSetUri(jwkSetUri)
                            .jwsAlgorithm(SignatureAlgorithm.RS256)
                            .build();
                    created.setJwtValidator(validators(projectId));
                    decoder = local = created;
                }
            }
        }
        return local;
    }

    private ApplicationException invalidToken() {
        return new ApplicationException(
                ErrorCase.UNAUTHORIZED,
                "No se pudo verificar la identidad del proveedor"
        );
    }
}
