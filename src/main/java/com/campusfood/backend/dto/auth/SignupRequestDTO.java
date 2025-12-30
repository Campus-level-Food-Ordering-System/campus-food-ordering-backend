package com.campusfood.backend.dto.auth;

import com.campusfood.backend.enums.AuthType;
import com.campusfood.backend.enums.Role;
import jakarta.validation.constraints.*;
import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class SignupRequestDTO {

    @NotBlank(message = "Username is required")
    private String username;

    @NotBlank(message = "Email is required")
    @Email(message = "Invalid email format")
    private String email;

    // Nullable for OAuth signup (GOOGLE)
    private String password;

    @NotNull(message = "Role is required")
    private Role role; // USER, ADMIN, VENDOR

    @NotNull(message = "Auth type is required")
    private AuthType authType; // PASSWORD, GOOGLE, etc.

    // Required only when role = USER
    private String collegeName;
    private String department;
    private String yearOfStudy;
}
