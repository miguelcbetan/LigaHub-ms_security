package com.uc.ms_security.dto.users;

import com.uc.ms_security.dto.roles.RoleResponseDTO;
import lombok.Value;

@Value
public class UserRoleResponseDTO {

    Long id;

    Long userId;

    RoleResponseDTO role;
}
