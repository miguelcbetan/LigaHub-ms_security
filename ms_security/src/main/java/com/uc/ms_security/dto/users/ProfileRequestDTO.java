package com.uc.ms_security.dto.users;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Past;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import lombok.Getter;
import lombok.Setter;

import java.time.LocalDate;

@Getter
@Setter
public class ProfileRequestDTO {

    @NotBlank(
            message = "El teléfono es obligatorio"
    )
    private String phone;

    @NotNull(
            message = "La fecha de nacimiento es obligatoria"
    )
    @Past(
            message = "La fecha de nacimiento debe estar en el pasado"
    )
    private LocalDate birthDate;

    /**
     * Imagen como data-URL. null = no cambiar la foto actual; "" = quitarla.
     */
    @Size(
            max = 500000,
            message = "La fotografía es demasiado grande"
    )
    @Pattern(
            regexp = "^$|^data:image/(png|jpeg|webp);base64,[A-Za-z0-9+/=]+$",
            message = "La fotografía debe ser una imagen PNG, JPEG o WebP"
    )
    private String photoUrl;
}
