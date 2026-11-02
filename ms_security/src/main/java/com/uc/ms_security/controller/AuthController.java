package com.uc.ms_security.controller;

import com.uc.ms_security.dto.AuthResponseDTO;
import com.uc.ms_security.dto.CurrentUserResponseDTO;
import com.uc.ms_security.dto.LoginRequestDTO;
import com.uc.ms_security.dto.OAuthLoginRequestDTO;
import com.uc.ms_security.dto.PasswordRecoveryRequestDTO;
import com.uc.ms_security.dto.PasswordRecoveryResponseDTO;
import com.uc.ms_security.dto.PasswordResetRequestDTO;
import com.uc.ms_security.dto.TwoFactorSettingsDTO;
import com.uc.ms_security.dto.TwoFactorVerifyRequestDTO;
import com.uc.ms_security.service.AuthService;
import com.uc.ms_security.service.OAuthService;
import com.uc.ms_security.service.PasswordRecoveryService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final OAuthService oAuthService;
    private final PasswordRecoveryService passwordRecoveryService;

    @PostMapping("/password-recovery")
    @ResponseStatus(HttpStatus.ACCEPTED)
    public PasswordRecoveryResponseDTO requestPasswordRecovery(
            @Valid @RequestBody PasswordRecoveryRequestDTO dto,
            HttpServletRequest request) {

        return passwordRecoveryService.requestRecovery(
                dto.email(), request.getRemoteAddr());
    }

    @PostMapping("/password-reset")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void resetPassword(@Valid @RequestBody PasswordResetRequestDTO dto) {
        passwordRecoveryService.resetPassword(dto.token(), dto.password());
    }

    @PostMapping("/login")
    public AuthResponseDTO login(
            @Valid @RequestBody LoginRequestDTO dto,
            HttpServletRequest request) {

        return authService.login(dto, request.getRemoteAddr());
    }

    @PostMapping("/2fa/verify")
    public AuthResponseDTO verifyTwoFactor(
            @Valid @RequestBody TwoFactorVerifyRequestDTO dto,
            HttpServletRequest request) {

        return authService.verifyTwoFactor(
                dto.challengeId(), dto.code(), request.getRemoteAddr());
    }

    /** Acceso con Google, GitHub o Microsoft: recibe el ID token de Firebase. */
    @PostMapping("/oauth")
    public AuthResponseDTO oauth(
            @Valid @RequestBody OAuthLoginRequestDTO dto,
            HttpServletRequest request) {

        return oAuthService.login(dto.idToken(), request.getRemoteAddr());
    }

    /** Revoca la sesión del token presentado. */
    @PostMapping("/logout")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void logout(@AuthenticationPrincipal Jwt jwt) {
        authService.logout(jwt.getId(), Long.valueOf(jwt.getSubject()));
    }

    @PutMapping("/2fa-settings")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void updateTwoFactor(
            @Valid @RequestBody TwoFactorSettingsDTO dto,
            Authentication authentication) {

        authService.setTwoFactorEnabled(
                Long.valueOf(authentication.getName()), dto.enabled());
    }

    /** Usuario del token con roles y permisos; solo exige estar autenticado. */
    @GetMapping("/me")
    public CurrentUserResponseDTO me(Authentication authentication) {
        return authService.currentUser(Long.valueOf(authentication.getName()));
    }
}
