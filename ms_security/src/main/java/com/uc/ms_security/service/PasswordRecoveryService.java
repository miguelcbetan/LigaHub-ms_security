package com.uc.ms_security.service;

import com.uc.ms_security.dto.auth.PasswordRecoveryResponseDTO;
import com.uc.ms_security.entity.AuthMethod;
import com.uc.ms_security.entity.PasswordResetToken;
import com.uc.ms_security.entity.User;
import com.uc.ms_security.exception.ApplicationException;
import com.uc.ms_security.exception.ErrorCase;
import com.uc.ms_security.repository.PasswordResetTokenRepository;
import com.uc.ms_security.repository.SessionRepository;
import com.uc.ms_security.repository.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.util.UriComponentsBuilder;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Locale;

@Service
public class PasswordRecoveryService {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int MAX_REQUESTS_PER_IP = 10;
    private static final int MAX_REQUESTS_PER_EMAIL = 3;
    private static final Duration REQUEST_WINDOW = Duration.ofMinutes(15);
    private static final String GENERIC_MESSAGE =
            "Si la cuenta existe y utiliza correo y contraseña, "
                    + "recibirás instrucciones para recuperar el acceso";

    private final UserRepository userRepository;
    private final PasswordResetTokenRepository tokenRepository;
    private final SessionRepository sessionRepository;
    private final PasswordEncoder passwordEncoder;
    private final EmailClient emailClient;
    private final RateLimiter rateLimiter;
    private final int ttlMinutes;
    private final String frontendUrl;

    public PasswordRecoveryService(
            UserRepository userRepository,
            PasswordResetTokenRepository tokenRepository,
            SessionRepository sessionRepository,
            PasswordEncoder passwordEncoder,
            EmailClient emailClient,
            RateLimiter rateLimiter,
            @Value("${security.password-reset.ttl-minutes:15}") int ttlMinutes,
            @Value("${security.password-reset.frontend-url:http://localhost:3000/recuperar}")
                    String frontendUrl) {
        this.userRepository = userRepository;
        this.tokenRepository = tokenRepository;
        this.sessionRepository = sessionRepository;
        this.passwordEncoder = passwordEncoder;
        this.emailClient = emailClient;
        this.rateLimiter = rateLimiter;
        this.ttlMinutes = ttlMinutes;
        this.frontendUrl = frontendUrl;
    }

    @Transactional
    public PasswordRecoveryResponseDTO requestRecovery(String rawEmail, String clientIp) {
        String email = rawEmail.trim().toLowerCase(Locale.ROOT);
        rateLimiter.check(
                "password-recovery|ip|" + clientIp,
                MAX_REQUESTS_PER_IP,
                REQUEST_WINDOW
        );
        rateLimiter.check(
                "password-recovery|email|" + email,
                MAX_REQUESTS_PER_EMAIL,
                REQUEST_WINDOW
        );

        User user = userRepository.findByEmail(email).orElse(null);
        if (user == null || user.getAuthMethod() != AuthMethod.LOCAL) {
            return new PasswordRecoveryResponseDTO(GENERIC_MESSAGE);
        }

        tokenRepository.invalidatePendingByUserId(user.getId());

        String rawToken = generateToken();
        LocalDateTime expiresAt = LocalDateTime.now().plusMinutes(ttlMinutes);

        PasswordResetToken resetToken = new PasswordResetToken();
        resetToken.setTokenHash(hash(rawToken));
        resetToken.setExpiresAt(expiresAt);
        resetToken.setUser(user);
        tokenRepository.save(resetToken);

        String resetUrl = UriComponentsBuilder.fromUriString(frontendUrl)
                .queryParam("token", rawToken)
                .build()
                .encode()
                .toUriString();
        emailClient.sendPasswordReset(email, resetUrl, ttlMinutes);

        return new PasswordRecoveryResponseDTO(GENERIC_MESSAGE);
    }

    @Transactional
    public void resetPassword(String rawToken, String newPassword) {
        PasswordResetToken resetToken = tokenRepository
                .findForReset(hash(rawToken))
                .orElseThrow(this::invalidToken);

        if (resetToken.isConsumed()
                || !resetToken.getExpiresAt().isAfter(LocalDateTime.now())
                || resetToken.getUser().getAuthMethod() != AuthMethod.LOCAL) {
            throw invalidToken();
        }

        User user = resetToken.getUser();
        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);

        resetToken.setConsumed(true);
        tokenRepository.save(resetToken);
        tokenRepository.invalidatePendingByUserId(user.getId());
        sessionRepository.deleteAllByUserId(user.getId());
    }

    @Scheduled(fixedDelayString = "PT1H", initialDelayString = "PT15M")
    @Transactional
    public void purgeExpiredTokens() {
        tokenRepository.deleteExpiredBefore(LocalDateTime.now().minusDays(1));
    }

    private String generateToken() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String hash(String token) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(token.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 no está disponible", e);
        }
    }

    private ApplicationException invalidToken() {
        return new ApplicationException(
                ErrorCase.INVALID_OPERATION,
                "La solicitud de recuperación es inválida o ha expirado"
        );
    }
}
