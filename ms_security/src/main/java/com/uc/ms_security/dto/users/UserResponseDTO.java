package com.uc.ms_security.dto.users;

import lombok.Value;

@Value
public class UserResponseDTO {
    Long id;
    String name;
    String email;
    boolean active;
}
