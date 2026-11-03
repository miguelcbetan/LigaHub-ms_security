package com.uc.ms_security.dto.users;

import com.uc.ms_security.dto.permissions.PermissionResponseDTO;
import lombok.Value;

import java.util.List;

@Value
public class CurrentUserResponseDTO {

    Long id;

    String name;

    String email;

    String photoUrl;

    List<String> roles;

    List<PermissionResponseDTO> permissions;

    boolean twoFactorEnabled;

    /** LOCAL (correo y contraseña) u OAUTH (proveedor externo). */
    String authMethod;
}
