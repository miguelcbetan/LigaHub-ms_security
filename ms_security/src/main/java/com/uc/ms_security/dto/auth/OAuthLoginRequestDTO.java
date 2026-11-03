package com.uc.ms_security.dto.auth;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record OAuthLoginRequestDTO(

        @NotBlank(message = "El token del proveedor es obligatorio")
        @Size(max = 8192, message = "El token del proveedor no es válido")
        String idToken) {
}
