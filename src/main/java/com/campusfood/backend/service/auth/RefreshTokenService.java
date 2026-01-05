package com.campusfood.backend.service.auth;

import com.campusfood.backend.entity.auth.RefreshToken;
import com.campusfood.backend.entity.auth.User;
import com.campusfood.backend.exception.auth.TokenRevokedException;
import com.campusfood.backend.repository.auth.RefreshTokenRepository;
import com.campusfood.backend.security.CustomUserDetails;
import com.campusfood.backend.security.jwt.JwtService;
import com.campusfood.backend.utils.TokenHashUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

/**
 * RefreshTokenService handles JWT refresh token rotation and validation
 * 
 * CORE RESPONSIBILITIES:
 * 1. Generate refresh tokens (store hashed version in DB)
 * 2. Validate refresh tokens (hash received token, compare with DB)
 * 3. Rotate refresh tokens (revoke old, create new)
 * 4. Detect token reuse (security breach protection)
 * 5. Revoke tokens (logout, password reset, etc.)
 * 
 * SECURITY FLOW:
 * 
 * SIGNUP/SIGNIN:
 * 1. Generate refresh token (JWT)
 * 2. Hash token using SHA256
 * 3. Store hash in DB
 * 4. Send actual token to client (httpOnly cookie)
 * 
 * REFRESH REQUEST:
 * 1. Client sends refresh token from cookie
 * 2. Hash token
 * 3. Query DB: find token where hash matches, NOT revoked, NOT expired
 * 4. If found: ROTATE (revoke old, create new)
 * 5. If revoked token is reused: REVOKE ALL tokens (security breach)
 * 
 * TOKEN REUSE DETECTION:
 * If a revoked token is used again → attacker has token AND DB was breached
 * → revoke ALL tokens for user → force re-login on all devices
 * → user alerted to change password
 */
@Slf4j
@Service
@RequiredArgsConstructor
@Transactional
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtService jwtService;

    /**
     * CREATE REFRESH TOKEN
     * Called after signin/signup
     * 
     * @param userDetails authenticated user
     * @param deviceId device identifier (mobile device ID, browser fingerprint)
     * @return plain text refresh token (to send to client)
     */
    public String createRefreshToken(CustomUserDetails userDetails, String deviceId) {
        // 1. Generate JWT refresh token
        String token = jwtService.generateRefreshToken(userDetails);

        // 2. Hash token for storage
        String tokenHash = TokenHashUtil.sha256(token);

        // 3. Extract expiration from JWT
        Instant expiresAt = jwtService.extractExpiration(token).toInstant();

        // 4. Save hashed token to DB
        RefreshToken refreshToken = RefreshToken.builder()
                .user(userDetails.getUser())
                .tokenHash(tokenHash)
                .deviceId(deviceId)
                .expiresAt(expiresAt)
                .revoked(false)
                .build();

        refreshTokenRepository.save(refreshToken);
        log.info("Created refresh token for user {} on device {}", userDetails.getUser().getId(), deviceId);

        // 5. Return plain token (only time it's sent to client)
        return token;
    }

    /**
     * VALIDATE AND ROTATE REFRESH TOKEN
     * Called when client sends /refresh request with refresh token cookie
     * 
     * ROTATION LOGIC:
     * 1. Hash received token
     * 2. Find token in DB (must not be revoked, must not be expired)
     * 3. If NOT found → possible token reuse attack
     * 4. If found → normal flow, revoke old token and create new one
     * 5. Return new token
     * 
     * TOKEN REUSE DETECTION:
     * If a revoked token is used → attacker has old token
     * → revoke ALL tokens for user (security breach)
     * → user must re-login
     * 
     * @param token plain text refresh token from cookie
     * @return new refresh token (for next rotation)
     * @throws TokenRevokedException if token is revoked/expired or reuse detected
     */
    public String rotateRefreshToken(String token) {
        // 1. Hash received token
        String tokenHash = TokenHashUtil.sha256(token);
        log.debug("Rotating token with hash: {}...", tokenHash.substring(0, 8));

        // 2. Validate JWT structure
        jwtService.validateToken(token);

        // 3. Find token in DB
        RefreshToken storedToken = refreshTokenRepository
                .findByTokenHashAndRevokedFalseAndExpiresAtAfter(tokenHash, Instant.now())
                .orElseThrow(() -> {
                    // Token not found or revoked/expired
                    // Check if it's a revoked token (reuse attempt)
                    refreshTokenRepository.findByTokenHash(tokenHash)
                            .ifPresent(revokedToken -> {
                                log.warn("SECURITY BREACH: Revoked token reused by user {}. Revoking all tokens.",
                                        revokedToken.getUser().getId());
                                // Revoke all tokens for this user
                                refreshTokenRepository.revokeAllForUser(revokedToken.getUser().getId());
                            });
                    return new TokenRevokedException("Refresh token is invalid, expired, or already revoked");
                });

        User user = storedToken.getUser();
        CustomUserDetails userDetails = new CustomUserDetails(user);
        String deviceId = storedToken.getDeviceId();

        // 4. Revoke old token
        refreshTokenRepository.revokeToken(tokenHash);
        log.info("Revoked old refresh token for user {}", user.getId());

        // 5. Create new refresh token
        String newToken = createRefreshToken(userDetails, deviceId);
        log.info("Created new refresh token for user {} (rotation)", user.getId());

        return newToken;
    }

    /**
     * REVOKE TOKEN
     * Used during logout from single device
     * 
     * @param token plain text refresh token
     */
    public void revokeToken(String token) {
        String tokenHash = TokenHashUtil.sha256(token);
        refreshTokenRepository.revokeToken(tokenHash);
        log.info("Revoked refresh token");
    }

    /**
     * REVOKE ALL TOKENS FOR USER
     * Used when:
     * - User resets password
     * - Security breach detected (revoked token reuse)
     * - Admin revokes user access
     * 
     * Effect: user is logged out from all devices
     * 
     * @param userId user's ID
     */
    public void revokeAllTokensForUser(Long userId) {
        refreshTokenRepository.revokeAllForUser(userId);
        log.warn("Revoked all refresh tokens for user {}", userId);
    }

    /**
     * VALIDATE REFRESH TOKEN
     * Check if token exists, is not revoked, and is not expired
     * 
     * @param token plain text refresh token
     * @return true if valid, false otherwise
     */
    public boolean isValidToken(String token) {
        try {
            String tokenHash = TokenHashUtil.sha256(token);
            return refreshTokenRepository
                    .findByTokenHashAndRevokedFalseAndExpiresAtAfter(tokenHash, Instant.now())
                    .isPresent();
        } catch (Exception e) {
            return false;
        }
    }
}
