package com.uc.ms_security.dto.permissions;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class PermissionRequestDTO {

    @NotBlank(message = "La url es obligatoria")
    @Size(
            max = 255,
            message = "La url no puede superar 255 caracteres"
    )
    private String url;

    @NotBlank(message = "El método es obligatorio")
    @Size(
            max = 10,
            message = "El método no puede superar 10 caracteres"
    )
    @Pattern(
            regexp = "(?i)^\\s*(GET|POST|PUT|PATCH|DELETE)\\s*$",
            message = "El método debe ser GET, POST, PUT, PATCH o DELETE"
    )
    private String method;

    @NotBlank(message = "El modelo es obligatorio")
    @Size(
            max = 255,
            message = "El modelo no puede superar 255 caracteres"
    )
    private String model;
}
