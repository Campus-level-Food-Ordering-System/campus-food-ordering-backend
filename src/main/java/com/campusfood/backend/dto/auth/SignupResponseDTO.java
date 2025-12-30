package com.campusfood.backend.dto.auth;

import com.campusfood.backend.enums.Role;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class SignupResponseDTO {

    private Long id;
    private String username;
    private String email;
    private Role role;
    private boolean emailVerified;
}
