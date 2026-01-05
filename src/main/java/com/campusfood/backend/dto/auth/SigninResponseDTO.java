package com.campusfood.backend.dto.auth;

import com.campusfood.backend.enums.Role;
import lombok.*;

/**
 * Response DTO for signin endpoint (POST /api/auth/signin)
 * 
 * accessToken: sent in response body, used for API requests
 * refreshToken: sent in HttpOnly secure cookie, NOT included in this DTO
 *
 * Example response:
 * {
 *   "id": 1,
 *   "username": "john_doe",
 *   "email": "john@example.com",
 *   "role": "USER",
 *   "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
 *   "tokenType": "Bearer",
 *   "expiresIn": 900
 * }
 */
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
    private String accessToken;
    @Builder.Default
    private String tokenType = "Bearer";
    @Builder.Default
    private long expiresIn = 900; // 15 minutes in seconds
}
