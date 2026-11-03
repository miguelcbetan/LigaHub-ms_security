package com.uc.ms_security.controller;

import com.uc.ms_security.dto.users.ProfileRequestDTO;
import com.uc.ms_security.dto.users.ProfileResponseDTO;
import com.uc.ms_security.dto.users.UserDetailResponseDTO;
import com.uc.ms_security.service.ProfileService;
import com.uc.ms_security.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

/**
 * Perfil del usuario autenticado. El usuario sale del token (claim `sub`),
 * nunca de la URL ni del cuerpo, así que nadie puede apuntar al perfil de otro.
 */
@RestController
@RequestMapping("/api/profile/me")
@RequiredArgsConstructor
public class MyProfileController {

    private final UserService userService;
    private final ProfileService profileService;

    @GetMapping
    public UserDetailResponseDTO find(Authentication authentication) {
        return userService.findByIdAndProfile(currentUserId(authentication));
    }

    @PutMapping
    public ProfileResponseDTO save(
            Authentication authentication,
            @Valid @RequestBody ProfileRequestDTO dto) {
        return profileService.save(currentUserId(authentication), dto);
    }

    private Long currentUserId(Authentication authentication) {
        return Long.valueOf(authentication.getName());
    }
}
