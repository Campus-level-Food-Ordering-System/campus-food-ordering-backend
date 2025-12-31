package com.campusfood.backend.dto.auth;

import com.campusfood.backend.enums.Role;
import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class SigninResponseDTO {

    private Long id;
    private String username;
    private String email;
    private Role role;

    // JWT tokens (will add later)
    private String accessToken;
    private String refreshToken;
}
