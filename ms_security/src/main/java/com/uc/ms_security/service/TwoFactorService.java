package com.uc.ms_security.service;

import com.uc.ms_security.dto.AuthResponseDTO;
import com.uc.ms_security.entity.TwoFactorChallenge;
import com.uc.ms_security.entity.User;
import com.uc.ms_security.exception.ApplicationException;
import com.uc.ms_security.exception.ErrorCase;
import com.uc.ms_security.repository.TwoFactorChallengeRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.HexFormat;
import java.util.UUID;

/**
 * Segundo factor por correo. Este servicio es la autoridad: genera el código,
 * guarda solo su HMAC, controla expiración, intentos y consumo único. El
 * microservicio de correo únicamente entrega el mensaje.
 */
@Service
public class TwoFactorService {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final TwoFactorChallengeRepository challengeRepository;
    private final EmailClient emailClient;
    private final AuthSessionService authSessionService;
    private final int ttlMinutes;
    private final int maxAttempts;
    private final byte[] hmacKey;

    public TwoFactorService(
            TwoFactorChallengeRepository challengeRepository,
            EmailClient emailClient,
            AuthSessionService authSessionService,
            @Value("${security.two-factor.ttl-minutes:5}") int ttlMinutes,
            @Value("${security.two-factor.max-attempts:5}") int maxAttempts,
            @Value("${security.two-factor.pepper:}") String pepper,
            @Value("${security.jwt.secret}") String jwtSecret) {

        this.challengeRepository = challengeRepository;
        this.emailClient = emailClient;
        this.authSessionService = authSessionService;
        this.ttlMinutes = ttlMinutes;
        this.maxAttempts = maxAttempts;
        // Sin pepper propio se deriva de la clave JWT, que ya es secreta.
        this.hmacKey = (pepper == null || pepper.isBlank() ? jwtSecret : pepper)
                .getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Crea el desafío y envía el código. Si el correo no sale, la
     * transacción se revierte y no queda ningún desafío utilizable.
     */
    @Transactional
    public AuthResponseDTO start(User user) {
        challengeRepository.invalidatePendingByUserId(user.getId());

        String code = String.format("%06d", RANDOM.nextInt(1_000_000));
        String challengeId = UUID.randomUUID().toString();
        LocalDateTime expiresAt = LocalDateTime.now().plusMinutes(ttlMinutes);

        TwoFactorChallenge challenge = new TwoFactorChallenge();
        challenge.setId(challengeId);
        challenge.setUser(user);
        challenge.setCodeHash(hash(challengeId, code));
        challenge.setExpiresAt(expiresAt);
        challengeRepository.save(challenge);

        emailClient.sendTwoFactorCode(user.getEmail(), code, ttlMinutes);

        return AuthResponseDTO.twoFactorPending(
                challengeId,
                expiresAt.atZone(ZoneId.systemDefault()).toInstant());
    }

    /**
     * El intento fallido debe persistir aunque se lance la excepción, por eso
     * no se revierte la transacción ante ApplicationException.
     */
    @Transactional(noRollbackFor = ApplicationException.class)
    public AuthResponseDTO verify(String challengeId, String code) {
        TwoFactorChallenge challenge = challengeRepository
                .findForVerification(challengeId)
                .orElseThrow(this::invalid);

        if (challenge.isConsumed()
                || challenge.getExpiresAt().isBefore(LocalDateTime.now())
                || challenge.getAttempts() >= maxAttempts) {
            throw invalid();
        }

        challenge.setAttempts(challenge.getAttempts() + 1);

        boolean matches = MessageDigest.isEqual(
                challenge.getCodeHash().getBytes(StandardCharsets.UTF_8),
                hash(challengeId, code).getBytes(StandardCharsets.UTF_8));

        if (!matches) {
            challengeRepository.save(challenge);
            throw invalid();
        }

        User user = challenge.getUser();
        if (!user.isActive()) {
            challenge.setConsumed(true);
            challengeRepository.save(challenge);
            throw new ApplicationException(
                    ErrorCase.FORBIDDEN, "La cuenta está deshabilitada");
        }

        challenge.setConsumed(true);
        challengeRepository.save(challenge);

        return authSessionService.start(user);
    }

    @Scheduled(fixedDelayString = "PT1H", initialDelayString = "PT15M")
    @Transactional
    public void purgeOld() {
        challengeRepository.deleteOlderThan(LocalDateTime.now().minusDays(1));
    }

    private ApplicationException invalid() {
        return new ApplicationException(
                ErrorCase.UNAUTHORIZED,
                "El código es incorrecto o ha expirado"
        );
    }

    private String hash(String challengeId, String code) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(hmacKey, "HmacSHA256"));
            return HexFormat.of().formatHex(mac.doFinal(
                    (challengeId + ":" + code).getBytes(StandardCharsets.UTF_8)));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HMAC-SHA256 no disponible", e);
        }
    }
}
