package com.uc.ms_security.service;

import com.uc.ms_security.entity.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class JwtService {

    public static final Duration TOKEN_DURATION = Duration.ofMinutes(15);

    private final JwtEncoder jwtEncoder;

    /** Token firmado más el jti con el que se registra la sesión. */
    public record IssuedToken(String token, String jti, Instant expiresAt) {
    }

    public IssuedToken generateToken(User user) {
        Instant now = Instant.now();
        Instant expiresAt = now.plus(TOKEN_DURATION);
        String jti = UUID.randomUUID().toString();

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("ms-security")
                .subject(user.getId().toString())
                .issuedAt(now)
                .expiresAt(expiresAt)
                .id(jti)
                .claim("email", user.getEmail())
                .build();

        JwsHeader header = JwsHeader
                .with(MacAlgorithm.HS256)
                .build();

        Jwt jwt = jwtEncoder.encode(JwtEncoderParameters.from(header, claims));

        return new IssuedToken(jwt.getTokenValue(), jti, expiresAt);
    }
}
