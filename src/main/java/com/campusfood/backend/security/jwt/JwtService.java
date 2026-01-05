package com.campusfood.backend.security.jwt;

import com.campusfood.backend.exception.auth.InvalidTokenException;
import com.campusfood.backend.exception.auth.TokenExpiredException;
import com.campusfood.backend.security.CustomUserDetails;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * JWT Service for generating and validating JWT tokens
 * 
 * TOKEN TYPES:
 * 1. Access Token: short-lived (15 minutes)
 *    - Used to authorize API requests
 *    - Sent in response body (Authorization: Bearer <token>)
 *    - Include user claims but not sensitive data
 * 
 * 2. Refresh Token: long-lived (7 days)
 *    - Used to get new access tokens
 *    - Sent in HttpOnly cookie (secure + httpOnly + sameSite)
 *    - Only token hash stored in DB (actual token sent once)
 *    - Includes deviceId to allow multiple sessions
 * 
 * TOKEN EXPIRY:
 * - Access: 15 minutes (900 seconds)
 * - Refresh: 7 days (604800 seconds)
 * 
 * SECURITY FEATURES:
 * - Signed with HS256 (HMAC with SHA-256)
 * - Expiration claims
 * - Device ID to track sessions
 * - Proper claim extraction with error handling
 */
@Service
public class JwtService {

    @Value("${jwt.secret-key}")
    private String secretKey;

    @Value("${jwt.access-token-expiry:900}") // 15 minutes
    private long accessTokenExpiry;

    @Value("${jwt.refresh-token-expiry:604800}") // 7 days
    private long refreshTokenExpiry;

    /**
     * Generate access token for user
     * 
     * Token claims:
     * - sub (subject): user email
     * - userId: user ID for quick lookup
     * - role: user role for authorization
     * - iat: issued at
     * - exp: expiration time
     * 
     * @param userDetails authenticated user details
     * @return JWT access token
     */
    public String generateAccessToken(CustomUserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", userDetails.getUser().getId());
        claims.put("email", userDetails.getUser().getEmail());
        claims.put("role", userDetails.getUser().getRole().name());

        return buildToken(claims, userDetails.getUsername(), accessTokenExpiry);
    }

    /**
     * Generate refresh token for user
     * 
     * Token claims:
     * - sub (subject): user email
     * - userId: user ID for quick lookup
     * - deviceId: device identifier for multiple sessions
     * - type: "refresh" to distinguish from access token
     * - iat: issued at
     * - exp: expiration time
     * 
     * deviceId should be provided by client and included in claims.
     * If deviceId is not provided, a random one is generated.
     * 
     * @param userDetails authenticated user details
     * @return JWT refresh token
     */
    public String generateRefreshToken(CustomUserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", userDetails.getUser().getId());
        claims.put("email", userDetails.getUser().getEmail());
        claims.put("type", "refresh");
        // deviceId will be set by service layer based on user's device
        claims.put("deviceId", "device_" + System.currentTimeMillis());

        return buildToken(claims, userDetails.getUsername(), refreshTokenExpiry);
    }

    /**
     * Build JWT token with given claims and expiry
     * 
     * @param claims custom claims to include in token
     * @param subject token subject (email)
     * @param expiryMillis expiration time in milliseconds
     * @return signed JWT token
     */
    private String buildToken(Map<String, Object> claims, String subject, long expiryMillis) {
        return Jwts.builder()
                .claims(claims)
                .subject(subject)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + (expiryMillis * 1000)))
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    /**
     * Extract user email from token
     * 
     * @param token JWT token
     * @return user email (subject claim)
     * @throws TokenExpiredException if token is expired
     * @throws InvalidTokenException if token is invalid
     */
    public String extractUsername(String token) {
        try {
            return parseClaims(token).getSubject();
        } catch (ExpiredJwtException e) {
            throw new TokenExpiredException("Token has expired");
        } catch (JwtException e) {
            throw new InvalidTokenException("Invalid token");
        }
    }

    /**
     * Extract user ID from token
     * 
     * @param token JWT token
     * @return user ID
     */
    public Long extractUserId(String token) {
        Object userId = parseClaims(token).get("userId");
        if (userId instanceof Number) {
            return ((Number) userId).longValue();
        }
        throw new InvalidTokenException("Invalid user ID in token");
    }

    /**
     * Extract device ID from token
     * Used to identify which device/session a token belongs to
     * 
     * @param token JWT token
     * @return device ID
     */
    public String extractDeviceId(String token) {
        Object deviceId = parseClaims(token).get("deviceId");
        if (deviceId != null) {
            return deviceId.toString();
        }
        throw new InvalidTokenException("No device ID in token");
    }

    /**
     * Get token expiration date
     * Used in refresh token rotation to set expiration in DB
     * 
     * @param token JWT token
     * @return expiration date
     */
    public Date extractExpiration(String token) {
        return parseClaims(token).getExpiration();
    }

    /**
     * Check if token is expired
     * 
     * @param token JWT token
     * @return true if expired, false otherwise
     */
    public boolean isTokenExpired(String token) {
        try {
            return extractExpiration(token).before(new Date());
        } catch (ExpiredJwtException e) {
            return true;
        }
    }

    /**
     * Validate token signature and expiration
     * 
     * @param token JWT token
     * @return true if token is valid
     * @throws TokenExpiredException if token is expired
     * @throws InvalidTokenException if token is invalid
     */
    public boolean validateToken(String token) {
        try {
            if (token == null || token.isEmpty()) {
                throw new InvalidTokenException("Invalid token: Token cannot be null or empty");
            }
            Jwts.parser()
                    .verifyWith(getSigningKey())
                    .build()
                    .parseSignedClaims(token);
            return true;
        } catch (ExpiredJwtException e) {
            throw new TokenExpiredException("Token has expired");
        } catch (JwtException | IllegalArgumentException e) {
            throw new InvalidTokenException("Invalid token: " + e.getMessage());
        }
    }

    /**
     * Parse JWT claims without validation
     * Used internally to extract claims
     * 
     * @param token JWT token
     * @return JWT claims
     */
    private Claims parseClaims(String token) {
        try {
            return Jwts.parser()
                    .verifyWith(getSigningKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (ExpiredJwtException e) {
            throw new TokenExpiredException("Token has expired");
        } catch (JwtException | IllegalArgumentException e) {
            throw new InvalidTokenException("Invalid token: " + e.getMessage());
        }
    }

    /**
     * Get signing key from secret
     * Converts secret string to proper key for HS256
     * 
     * @return signing key
     */
    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(secretKey.getBytes());
    }
}
