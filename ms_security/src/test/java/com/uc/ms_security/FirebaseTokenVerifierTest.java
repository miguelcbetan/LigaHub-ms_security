package com.uc.ms_security;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.uc.ms_security.exception.ApplicationException;
import com.uc.ms_security.exception.ErrorCase;
import com.uc.ms_security.service.FirebaseTokenVerifier.FirebaseIdentity;
import com.uc.ms_security.service.NimbusFirebaseTokenVerifier;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Verifica con firmas RSA reales (claves locales de prueba) que el
 * verificador exige firma, emisor, audiencia, expiración, sub, auth_time y un
 * proveedor admitido. Usa los mismos validadores que el decodificador real.
 */
class FirebaseTokenVerifierTest {

    private static final String PROJECT = "proyecto-de-prueba";

    private static RSAKey trustedKey;
    private static RSAKey strangerKey;
    private static NimbusFirebaseTokenVerifier verifier;

    @BeforeAll
    static void setUp() throws Exception {
        trustedKey = newKey("trusted");
        strangerKey = newKey("trusted"); // mismo kid, otra clave: firma no coincide

        NimbusJwtDecoder decoder = NimbusJwtDecoder
                .withPublicKey(trustedKey.toRSAPublicKey())
                .signatureAlgorithm(SignatureAlgorithm.RS256)
                .build();
        decoder.setJwtValidator(NimbusFirebaseTokenVerifier.validators(PROJECT));
        verifier = new NimbusFirebaseTokenVerifier(PROJECT, decoder);
    }

    private static RSAKey newKey(String kid) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        return new RSAKey.Builder((RSAPublicKey) pair.getPublic())
                .privateKey((RSAPrivateKey) pair.getPrivate())
                .keyID(kid)
                .build();
    }

    private String sign(RSAKey key, Consumer<JwtClaimsSet.Builder> customize) {
        JwtClaimsSet.Builder claims = JwtClaimsSet.builder()
                .issuer("https://securetoken.google.com/" + PROJECT)
                .audience(List.of(PROJECT))
                .subject("firebase-uid-123")
                .issuedAt(Instant.now().minusSeconds(30))
                .expiresAt(Instant.now().plusSeconds(3000))
                .claim("auth_time", Instant.now().minusSeconds(30).getEpochSecond())
                .claim("email", "externo@liga.test")
                .claim("email_verified", true)
                .claim("name", "Persona Externa")
                .claim("firebase", Map.of("sign_in_provider", "google.com"));
        customize.accept(claims);

        NimbusJwtEncoder encoder = new NimbusJwtEncoder(
                new ImmutableJWKSet<>(new JWKSet(key)));
        return encoder.encode(JwtEncoderParameters.from(
                JwsHeader.with(SignatureAlgorithm.RS256).keyId(key.getKeyID()).build(),
                claims.build())).getTokenValue();
    }

    private void assertRejected(String token) {
        assertThatThrownBy(() -> verifier.verify(token))
                .isInstanceOfSatisfying(ApplicationException.class, e ->
                        assertThat(e.getErrorCase()).isEqualTo(ErrorCase.UNAUTHORIZED));
    }

    @Test
    void validTokenYieldsVerifiedIdentity() {
        FirebaseIdentity identity = verifier.verify(sign(trustedKey, c -> { }));

        assertThat(identity.uid()).isEqualTo("firebase-uid-123");
        assertThat(identity.provider()).isEqualTo("google.com");
        assertThat(identity.email()).isEqualTo("externo@liga.test");
        assertThat(identity.emailVerified()).isTrue();
    }

    @Test
    void githubAndMicrosoftProvidersAreAccepted() {
        for (String provider : List.of("github.com", "microsoft.com")) {
            FirebaseIdentity identity = verifier.verify(sign(trustedKey, c ->
                    c.claim("firebase", Map.of("sign_in_provider", provider))));
            assertThat(identity.provider()).isEqualTo(provider);
        }
    }

    @Test
    void tokenSignedWithAnotherKeyIsRejected() {
        assertRejected(sign(strangerKey, c -> { }));
    }

    @Test
    void wrongAudienceIsRejected() {
        assertRejected(sign(trustedKey, c -> c.audience(List.of("otro-proyecto"))));
    }

    @Test
    void wrongIssuerIsRejected() {
        assertRejected(sign(trustedKey, c ->
                c.issuer("https://securetoken.google.com/otro-proyecto")));
    }

    @Test
    void expiredTokenIsRejected() {
        assertRejected(sign(trustedKey, c -> c
                .issuedAt(Instant.now().minusSeconds(7200))
                .expiresAt(Instant.now().minusSeconds(3600))));
    }

    @Test
    void missingSubjectIsRejected() {
        assertRejected(sign(trustedKey, c -> c.claims(m -> m.remove("sub"))));
    }

    @Test
    void futureAuthTimeIsRejected() {
        assertRejected(sign(trustedKey, c ->
                c.claim("auth_time", Instant.now().plusSeconds(3600).getEpochSecond())));
    }

    @Test
    void passwordProviderOrUnknownProviderIsRejected() {
        assertRejected(sign(trustedKey, c ->
                c.claim("firebase", Map.of("sign_in_provider", "password"))));
        assertRejected(sign(trustedKey, c -> c.claims(m -> m.remove("firebase"))));
    }

    @Test
    void garbageIsRejected() {
        assertRejected("esto-no-es-un-jwt");
    }

    @Test
    void missingProjectConfigurationReportsUnavailable() {
        NimbusFirebaseTokenVerifier unconfigured = new NimbusFirebaseTokenVerifier(
                "", "https://example.invalid/jwks");

        assertThatThrownBy(() -> unconfigured.verify("cualquiera"))
                .isInstanceOfSatisfying(ApplicationException.class, e ->
                        assertThat(e.getErrorCase()).isEqualTo(ErrorCase.SERVICE_UNAVAILABLE));
    }
}
