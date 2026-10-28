package com.uc.ms_security.service;

import com.uc.ms_security.dto.AuthResponseDTO;
import com.uc.ms_security.dto.CurrentUserResponseDTO;
import com.uc.ms_security.dto.LoginRequestDTO;
import com.uc.ms_security.entity.AuthMethod;
import com.uc.ms_security.entity.Profile;
import com.uc.ms_security.entity.User;
import com.uc.ms_security.exception.ApplicationException;
import com.uc.ms_security.exception.ErrorCase;
import com.uc.ms_security.mapper.PermissionMapper;
import com.uc.ms_security.repository.PermissionRepository;
import com.uc.ms_security.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.util.Locale;

@Service
public class AuthService {

    private static final Logger log = LoggerFactory.getLogger(AuthService.class);

    private static final int MAX_LOGIN_ATTEMPTS = 8;
    private static final Duration LOGIN_WINDOW = Duration.ofMinutes(10);
    private static final int MAX_VERIFY_ATTEMPTS_PER_IP = 20;

    private final UserRepository userRepository;
    private final PermissionRepository permissionRepository;
    private final PermissionMapper permissionMapper;
    private final PasswordEncoder passwordEncoder;
    private final AuthSessionService authSessionService;
    private final TwoFactorService twoFactorService;
    private final RateLimiter rateLimiter;

    /** Hash de relleno para que un correo inexistente cueste lo mismo que uno real. */
    private final String dummyHash;

    public AuthService(
            UserRepository userRepository,
            PermissionRepository permissionRepository,
            PermissionMapper permissionMapper,
            PasswordEncoder passwordEncoder,
            AuthSessionService authSessionService,
            TwoFactorService twoFactorService,
            RateLimiter rateLimiter) {
        this.userRepository = userRepository;
        this.permissionRepository = permissionRepository;
        this.permissionMapper = permissionMapper;
        this.passwordEncoder = passwordEncoder;
        this.authSessionService = authSessionService;
        this.twoFactorService = twoFactorService;
        this.rateLimiter = rateLimiter;
        this.dummyHash = passwordEncoder.encode("no-es-una-contraseña-real");
    }

    /**
     * Paso 1 del acceso con contraseña. Si el usuario tiene el segundo factor
     * activo solo se verifican las credenciales y se devuelve un desafío (sin
     * sesión); en otro caso se crea la sesión.
     */
    public AuthResponseDTO login(LoginRequestDTO dto, String clientIp) {
        String email = dto.getEmail() == null
                ? "" : dto.getEmail().trim().toLowerCase(Locale.ROOT);
        String rateKey = "login|" + email + "|" + clientIp;

        rateLimiter.check(rateKey, MAX_LOGIN_ATTEMPTS, LOGIN_WINDOW);

        User user = userRepository.findByEmail(email).orElse(null);

        boolean validPassword = passwordEncoder.matches(
                dto.getPassword(),
                user != null ? user.getPassword() : dummyHash
        );

        if (user == null || !validPassword || user.getAuthMethod() != AuthMethod.LOCAL) {
            log.info("Intento de acceso fallido");
            throw unauthorized();
        }

        if (!user.isActive()) {
            log.info("Acceso rechazado: cuenta deshabilitada (usuario {})", user.getId());
            throw new ApplicationException(
                    ErrorCase.FORBIDDEN,
                    "El usuario está desactivado"
            );
        }

        rateLimiter.reset(rateKey);

        if (user.isTwoFactorEnabled()) {
            return twoFactorService.start(user);
        }

        return authSessionService.start(user);
    }

    /** Paso 2: el acceso solo se completa con el código correcto. */
    public AuthResponseDTO verifyTwoFactor(
            String challengeId,
            String code,
            String clientIp) {

        rateLimiter.check("2fa|" + clientIp,
                MAX_VERIFY_ATTEMPTS_PER_IP, LOGIN_WINDOW);

        return twoFactorService.verify(challengeId, code);
    }

    @Transactional
    public void setTwoFactorEnabled(Long userId, boolean enabled) {
        User user = userRepository.findById(userId)
                .filter(User::isActive)
                .orElseThrow(this::unauthorized);

        if (user.getAuthMethod() != AuthMethod.LOCAL) {
            throw new ApplicationException(
                    ErrorCase.INVALID_OPERATION,
                    "El segundo factor solo aplica al acceso con correo y contraseña"
            );
        }

        user.setTwoFactorEnabled(enabled);
        userRepository.save(user);
    }

    public void logout(String jti, Long userId) {
        authSessionService.revoke(jti, userId);
    }

    /**
     * Identidad del usuario del token con sus roles y permisos efectivos.
     * No pasa por la autorización dinámica: cualquier usuario activo puede
     * consultarse a sí mismo, aunque su rol no tenga ningún permiso.
     */
    @Transactional(readOnly = true)
    public CurrentUserResponseDTO currentUser(Long userId) {
        User user = userRepository.findWithRolesById(userId)
                .filter(User::isActive)
                .orElseThrow(this::unauthorized);

        Profile profile = user.getProfile();

        return new CurrentUserResponseDTO(
                user.getId(),
                user.getName(),
                user.getEmail(),
                profile != null ? profile.getPhotoUrl() : null,
                user.getUserRoles().stream()
                        .map(userRole -> userRole.getRole().getName())
                        .toList(),
                permissionMapper.toResponseDTOList(
                        permissionRepository.findAllByUserId(userId)
                ),
                user.isTwoFactorEnabled(),
                user.getAuthMethod().name()
        );
    }

    private ApplicationException unauthorized() {
        return new ApplicationException(
                ErrorCase.UNAUTHORIZED,
                "Credenciales incorrectas"
        );
    }
}
