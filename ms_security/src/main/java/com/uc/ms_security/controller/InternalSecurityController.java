package com.uc.ms_security.controller;

import com.uc.ms_security.service.PermissionService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/internal/security")
@RequiredArgsConstructor
public class InternalSecurityController {

    private final PermissionService permissionService;

    @PostMapping("/permissions-validation")
    public PermissionValidationResponse validatePermission(
            @Valid @RequestBody PermissionValidationRequest request,
            Authentication authentication) {
        Long userId = Long.valueOf(authentication.getName());
        boolean allowed = permissionService.hasPermission(
                userId,
                request.method(),
                request.url()
        );
        return new PermissionValidationResponse(allowed);
    }

    public record PermissionValidationRequest(
            @NotBlank String url,
            @NotBlank String method
    ) {
    }

    public record PermissionValidationResponse(boolean allowed) {
    }
}
