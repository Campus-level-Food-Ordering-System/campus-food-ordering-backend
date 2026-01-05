package com.campusfood.backend.dto.auth;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Response DTO for logout endpoint (POST /api/auth/logout)
 * 
 * Example response:
 * {
 *   "message": "Logged out successfully"
 * }
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class LogoutResponseDTO {

    private String message;
}
