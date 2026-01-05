package com.campusfood.backend.dto.auth;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Response DTO for refresh token endpoint (POST /api/auth/refresh)
 * 
 * Example response:
 * {
 *   "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
 *   "tokenType": "Bearer",
 *   "expiresIn": 900
 * }
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RefreshTokenResponseDTO {

    private String accessToken;
    @Builder.Default
    private String tokenType = "Bearer";
    private long expiresIn; // in seconds (15 minutes = 900 seconds)
}
