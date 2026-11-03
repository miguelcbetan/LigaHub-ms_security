package com.uc.ms_security.dto.roles;

import com.uc.ms_security.dto.users.UserResponseDTO;
import lombok.Value;

@Value
public class RoleUserResponseDTO {

    Long id;

    Long roleId;

    UserResponseDTO user;
}
