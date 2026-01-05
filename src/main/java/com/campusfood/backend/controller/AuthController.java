
package com.campusfood.backend.controller;

import com.campusfood.backend.dto.auth.*;
import com.campusfood.backend.entity.auth.User;
import com.campusfood.backend.service.auth.AuthService;
import com.campusfood.backend.service.auth.RefreshTokenService;
import com.campusfood.backend.utils.ApiResponse;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.web.bind.annotation.*;

import java.time.Duration;
import java.util.List;

/**
 * AuthController: REST API endpoints for authentication and authorization
 * 
 * All endpoints use standard HTTP status codes:
 * - 200: Success
 * - 201: Created
 * - 400: Bad Request (validation failed)
 * - 401: Unauthorized (invalid credentials)
 * - 403: Forbidden (access denied)
 * - 500: Server Error
 * 
 * Refresh tokens are sent as HttpOnly cookies (secure, not accessible from JavaScript)
 * Access tokens are sent in response body (Authorization: Bearer <token>)
 */
@Slf4j
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;
    private final RefreshTokenService refreshTokenService;

    public AuthController(AuthService authService, RefreshTokenService refreshTokenService) {
        this.authService = authService;
        this.refreshTokenService = refreshTokenService;
    }

    // ========================================
    // 1. SIGNUP
    // ========================================

    /**
     * POST /api/auth/signup
     * Create new user account
     * 
     * Request body:
     * {
     *   "username": "john_doe",
     *   "email": "john@example.com",
     *   "password": "SecurePassword123!",
     *   "role": "USER",
     *   "authType": "PASSWORD",
     *   "collegeName": "XYZ College",
     *   "department": "Computer Science",
     *   "yearOfStudy": "2"
     * }
     * 
     * Response:
     * {
     *   "message": "User signed up successfully",
     *   "status": 201,
     *   "data": {
     *     "id": 1,
     *     "username": "john_doe",
     *     "email": "john@example.com",
     *     "role": "USER",
     *     "emailVerified": false
     *   }
     * }
     * 
     * NOTE: User cannot signin until email is verified
     */
    @PostMapping("/signup")
    public ApiResponse<SignupResponseDTO> signup(
            @Valid @RequestBody SignupRequestDTO request) {
        log.info("Signup endpoint called");
        SignupResponseDTO response = authService.signup(request);
        return ApiResponse.of("User signed up successfully. Check email for verification code.", 201, response);
    }

    // ========================================
    // 2. EMAIL VERIFICATION
    // ========================================

    /**
     * POST /api/auth/verify-email
     * Verify user's email using verification code
     * 
     * Request body:
     * {
     *   "email": "john@example.com",
     *   "code": "123456"
     * }
     * 
     * Response:
     * {
     *   "message": "Email verified successfully",
     *   "status": 200,
     *   "data": null
     * }
     * 
     * NOTE: User can signin after email is verified
     */
    @PostMapping("/verify-email")
    public ApiResponse<Void> verifyEmail(
            @Valid @RequestBody VerifyEmailRequestDTO request) {
        log.info("Email verification endpoint called for: {}", request.getEmail());
        authService.verifyEmail(request.getEmail(), request.getCode());
        return ApiResponse.of("Email verified successfully. You can now signin.", 200, null);
    }

    /**
     * POST /api/auth/resend-verification-code
     * Resend verification code to email
     * 
     * Request body:
     * {
     *   "email": "john@example.com"
     * }
     * 
     * Response:
     * {
     *   "message": "Verification code sent successfully",
     *   "status": 200,
     *   "data": null
     * }
     */
    @PostMapping("/resend-verification-code")
    public ApiResponse<Void> resendVerificationCode(
            @Valid @RequestBody ResendCodeRequestDTO request) {
        log.info("Resend verification code endpoint called for: {}", request.getEmail());
        authService.resendVerificationCode(request.getEmail());
        return ApiResponse.of("Verification code sent to your email. Code expires in 15 minutes.", 200, null);
    }

    // ========================================
    // 3. SIGNIN
    // ========================================

    /**
     * POST /api/auth/signin
     * Authenticate user and generate access token
     * 
     * Request body:
     * {
     *   "email": "john@example.com",
     *   "password": "SecurePassword123!",
     *   "role": "USER"
     * }
     * 
     * Response headers:
     * Set-Cookie: REFRESH_TOKEN=<refreshToken>; HttpOnly; Secure; SameSite=Lax; Path=/api/auth/refresh; Max-Age=604800
     * 
     * Response body:
     * {
     *   "message": "User signed in successfully",
     *   "status": 200,
     *   "data": {
     *     "id": 1,
     *     "username": "john_doe",
     *     "email": "john@example.com",
     *     "role": "USER",
     *     "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
     *     "tokenType": "Bearer",
     *     "expiresIn": 900
     *   }
     * }
     * 
     * CLIENT USAGE:
     * 1. Extract accessToken from response
     * 2. Use in API requests: Authorization: Bearer <accessToken>
     * 3. Refresh token is automatically stored in cookie
     * 4. When access token expires, call /refresh endpoint
     */
    @PostMapping("/signin")
    public ApiResponse<SigninResponseDTO> signin(
            @Valid @RequestBody SigninRequestDTO request,
            HttpServletResponse response) {
        log.info("Signin endpoint called for: {}", request.getEmail());

        // 1. Authenticate user
        SigninResponseDTO result = authService.signin(request);

        // 2. Extract refresh token from service (we need to regenerate it here for the cookie)
        // Note: in production, the refresh token should be returned from signin
        String deviceId = "device_" + System.currentTimeMillis();
        // For now, we'll set a secure cookie with instructions

        // 3. Set refresh token in HttpOnly cookie
        ResponseCookie refreshCookie = ResponseCookie
                .from("REFRESH_TOKEN", generateMockRefreshToken())
                .httpOnly(true)
                .secure(false) // set to true in production (HTTPS only)
                .sameSite("Lax")
                .path("/api/auth/refresh")
                .maxAge(Duration.ofDays(7))
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, refreshCookie.toString());
        log.info("Refresh token cookie set for user: {}", result.getId());

        return ApiResponse.of("User signed in successfully", 200, result);
    }

    // ========================================
    // 4. REFRESH TOKEN
    // ========================================

    /**
     * POST /api/auth/refresh
     * Get new access token using refresh token (with token rotation)
     * 
     * Headers:
     * Cookie: REFRESH_TOKEN=<refreshToken>
     * 
     * Response headers:
     * Set-Cookie: REFRESH_TOKEN=<newRefreshToken>; ...
     * 
     * Response body:
     * {
     *   "message": "Access token refreshed successfully",
     *   "status": 200,
     *   "data": {
     *     "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
     *     "tokenType": "Bearer",
     *     "expiresIn": 900
     *   }
     * }
     * 
     * SECURITY:
     * - Old refresh token is revoked (rotation)
     * - If revoked token is reused → all tokens for user are revoked
     * - Client must update cookie with new refresh token
     */
    @PostMapping("/refresh")
    public ApiResponse<RefreshTokenResponseDTO> refresh(
            @CookieValue(value = "REFRESH_TOKEN", required = false) String refreshToken,
            HttpServletResponse response) {
        log.info("Refresh token endpoint called");

        if (refreshToken == null) {
            throw new IllegalArgumentException("Refresh token not found in cookie. Please signin again.");
        }

        try {
            // 1. Rotate refresh token (validate + revoke old + create new)
            String newRefreshToken = refreshTokenService.rotateRefreshToken(refreshToken);
            log.info("Refresh token rotated successfully");

            // 2. Generate new access token
            // (in real implementation, extract user from token and generate)
            String newAccessToken = generateMockAccessToken();

            // 3. Set new refresh token in cookie
            ResponseCookie newCookie = ResponseCookie
                    .from("REFRESH_TOKEN", newRefreshToken)
                    .httpOnly(true)
                    .secure(false)
                    .sameSite("Lax")
                    .path("/api/auth/refresh")
                    .maxAge(Duration.ofDays(7))
                    .build();

            response.addHeader(HttpHeaders.SET_COOKIE, newCookie.toString());

            return ApiResponse.of("Access token refreshed successfully", 200,
                    RefreshTokenResponseDTO.builder()
                            .accessToken(newAccessToken)
                            .tokenType("Bearer")
                            .expiresIn(900)
                            .build());

        } catch (Exception e) {
            log.error("Refresh failed: {}", e.getMessage());
            throw e;
        }
    }

    // ========================================
    // 5. LOGOUT
    // ========================================

    /**
     * POST /api/auth/logout
     * Logout user from current device (revoke refresh token)
     * 
     * Headers:
     * Cookie: REFRESH_TOKEN=<refreshToken>
     * 
     * Response:
     * {
     *   "message": "Logged out successfully",
     *   "status": 200,
     *   "data": null
     * }
     * 
     * NOTE: Clears refresh token cookie
     */
    @PostMapping("/logout")
    public ApiResponse<Void> logout(
            @CookieValue(value = "REFRESH_TOKEN", required = false) String refreshToken,
            HttpServletResponse response) {
        log.info("Logout endpoint called");

        if (refreshToken != null) {
            // Revoke refresh token
            refreshTokenService.revokeToken(refreshToken);
            log.info("Refresh token revoked");
        }

        // Clear refresh token cookie
        ResponseCookie clearCookie = ResponseCookie
                .from("REFRESH_TOKEN", "")
                .httpOnly(true)
                .secure(false)
                .sameSite("Lax")
                .path("/api/auth/refresh")
                .maxAge(0)
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, clearCookie.toString());
        log.info("Refresh token cookie cleared");

        return ApiResponse.of("Logged out successfully", 200, null);
    }

    // ========================================
    // 6. PASSWORD RESET
    // ========================================

    /**
     * POST /api/auth/forgot-password
     * Initiate password reset (send reset code to email)
     * 
     * Request body:
     * {
     *   "email": "john@example.com"
     * }
     * 
     * Response:
     * {
     *   "message": "If email exists, password reset code will be sent",
     *   "status": 200,
     *   "data": null
     * }
     * 
     * NOTE: Returns same message regardless of whether email exists (security)
     */
    @PostMapping("/forgot-password")
    public ApiResponse<Void> forgotPassword(
            @Valid @RequestBody ForgotPasswordRequestDTO request) {
        log.info("Forgot password endpoint called for: {}", request.getEmail());
        authService.forgotPassword(request);
        return ApiResponse.of("If email exists, password reset code will be sent to it. Code expires in 1 hour.", 200, null);
    }

    /**
     * POST /api/auth/reset-password
     * Reset password using reset code
     * 
     * Request body:
     * {
     *   "email": "john@example.com",
     *   "resetCode": "123456",
     *   "newPassword": "NewSecurePassword123!"
     * }
     * 
     * Response:
     * {
     *   "message": "Password reset successfully. Please signin with new password.",
     *   "status": 200,
     *   "data": null
     * }
     * 
     * SECURITY:
     * - All refresh tokens for user are revoked
     * - User must signin again with new password
     */
    @PostMapping("/reset-password")
    public ApiResponse<Void> resetPassword(
            @Valid @RequestBody ResetPasswordRequestDTO request) {
        log.info("Reset password endpoint called for: {}", request.getEmail());
        authService.resetPassword(request);
        return ApiResponse.of("Password reset successfully. Please signin with your new password.", 200, null);
    }

    // ========================================
    // 7. USER LISTING (ADMIN ONLY)
    // ========================================

    /**
     * GET /api/auth/users
     * List all users in system
     * 
     * ADMIN ONLY endpoint
     * 
     * Response:
     * {
     *   "message": "Users fetched successfully",
     *   "status": 200,
     *   "data": [
     *     {
     *       "id": 1,
     *       "username": "john_doe",
     *       "email": "john@example.com",
     *       ...
     *     }
     *   ]
     * }
     */
    @GetMapping("/users")
    public ApiResponse<List<User>> getAllUsers() {
        log.info("Get all users endpoint called");
        List<User> users = authService.getAllUsers();
        return ApiResponse.of("Users fetched successfully", 200, users);
    }

    // ========================================
    // HELPER METHODS
    // ========================================

    private String generateMockRefreshToken() {
        // In real implementation, this comes from RefreshTokenService
        return "mock_refresh_token_" + System.currentTimeMillis();
    }

    private String generateMockAccessToken() {
        // In real implementation, this comes from JwtService
        return "mock_access_token_" + System.currentTimeMillis();    }
}