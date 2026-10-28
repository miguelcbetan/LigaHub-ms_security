package com.uc.ms_security.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public record TwoFactorVerifyRequestDTO(

        @NotBlank(message = "El desafío es obligatorio")
        @Pattern(
                regexp = "^[0-9a-fA-F\\-]{36}$",
                message = "El desafío no es válido"
        )
        String challengeId,

        @NotBlank(message = "El código es obligatorio")
        @Pattern(
                regexp = "^\\d{6}$",
                message = "El código debe tener 6 dígitos"
        )
        String code) {
}
