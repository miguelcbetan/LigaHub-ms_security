package com.uc.ms_security.dto;

import jakarta.validation.constraints.NotNull;

public record TwoFactorSettingsDTO(

        @NotNull(message = "Indica si el segundo factor debe estar activo")
        Boolean enabled) {
}
