package com.uc.ms_security.dto.roles;

import com.uc.ms_security.dto.permissions.PermissionResponseDTO;
import lombok.Value;

@Value
public class RolePermissionResponseDTO {

    Long id;

    Long roleId;

    PermissionResponseDTO permission;
}
