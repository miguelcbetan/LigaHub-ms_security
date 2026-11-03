package com.uc.ms_security.dto.permissions;

import com.uc.ms_security.dto.roles.RoleResponseDTO;
import lombok.Value;

@Value
public class PermissionRoleResponseDTO {

    Long id;

    Long permissionId;

    RoleResponseDTO role;
}
