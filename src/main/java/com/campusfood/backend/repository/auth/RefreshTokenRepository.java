package com.campusfood.backend.repository.auth;

import com.campusfood.backend.entity.auth.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * Repository for RefreshToken entity.
 * 
 * KEY SECURITY OPERATIONS:
 * 1. findByTokenHashAndRevokedFalseAndExpiresAtAfter: validate token
 * 2. revokeByUserAndDevice: logout from one device
 * 3. revokeAllForUser: password reset (force re-login on all devices)
 * 4. deleteRevokedOrExpired: scheduled cleanup job
 */
@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    /**
     * Validate refresh token
     * 
     * Conditions:
     * - Token hash matches
     * - NOT revoked
     * - NOT expired (expiresAt is after current time)
     * 
     * @param tokenHash hashed refresh token from DB
     * @param now current timestamp
     * @return Optional containing token if valid
     */
    Optional<RefreshToken> findByTokenHashAndRevokedFalseAndExpiresAtAfter(
            String tokenHash,
            Instant now
    );

    /**
     * Find all active refresh tokens for a user
     * Used to detect reuse of revoked tokens and revoke all if breach detected
     * 
     * @param userId user's ID
     * @return List of user's refresh tokens
     */
    @Query("""
        SELECT rt
        FROM RefreshToken rt
        WHERE rt.user.id = :userId
        ORDER BY rt.createdAt DESC
    """)
    List<RefreshToken> findAllByUserId(@Param("userId") Long userId);

    /**
     * Find all active tokens for a specific user and device
     * Used to detect if user already has a session on this device
     * 
     * @param userId user's ID
     * @param deviceId device identifier
     * @return List of tokens for user+device combination
     */
    @Query("""
        SELECT rt
        FROM RefreshToken rt
        WHERE rt.user.id = :userId
          AND rt.deviceId = :deviceId
          AND rt.revoked = false
        ORDER BY rt.createdAt DESC
    """)
    List<RefreshToken> findAllActiveByUserAndDevice(
            @Param("userId") Long userId,
            @Param("deviceId") String deviceId
    );

    /**
     * Find token by hash (used for validation)
     * 
     * @param tokenHash hashed token value
     * @return Optional containing token if found
     */
    Optional<RefreshToken> findByTokenHash(String tokenHash);

    /**
     * LOGOUT FROM ONE DEVICE
     * Revoke single refresh token (revoke previous token during rotation)
     * 
     * @param tokenHash token to revoke
     */
    @Modifying
    @Query("""
        UPDATE RefreshToken rt
        SET rt.revoked = true
        WHERE rt.tokenHash = :tokenHash
    """)
    void revokeToken(@Param("tokenHash") String tokenHash);

    /**
     * LOGOUT FROM ONE DEVICE
     * Revoke all tokens for user + specific device
     * Used when user clicks "Logout" on specific device
     * 
     * @param userId user's ID
     * @param deviceId device to logout from
     */
    @Modifying
    @Query("""
        UPDATE RefreshToken rt
        SET rt.revoked = true
        WHERE rt.user.id = :userId
          AND rt.deviceId = :deviceId
    """)
    void revokeByUserAndDevice(
            @Param("userId") Long userId,
            @Param("deviceId") String deviceId
    );

    /**
     * LOGOUT FROM ALL DEVICES
     * Revoke ALL refresh tokens for a user
     * 
     * Triggered when:
     * - User resets password
     * - Detected token reuse (security breach)
     * - Admin revokes user access
     * 
     * @param userId user's ID
     */
    @Modifying
    @Query("""
        UPDATE RefreshToken rt
        SET rt.revoked = true
        WHERE rt.user.id = :userId
    """)
    void revokeAllForUser(@Param("userId") Long userId);

    /**
     * CLEANUP JOB (runs every hour)
     * Delete tokens that are no longer useful
     * 
     * @param now current timestamp
     */
    @Modifying
    @Query("""
        DELETE FROM RefreshToken rt
        WHERE rt.revoked = true
           OR rt.expiresAt < :now
    """)
    void deleteRevokedOrExpired(@Param("now") Instant now);

    /**
     * Count active tokens for a user
     * Can be used to limit concurrent sessions
     * 
     * @param userId user's ID
     * @return number of active tokens
     */
    @Query("""
        SELECT COUNT(rt)
        FROM RefreshToken rt
        WHERE rt.user.id = :userId
          AND rt.revoked = false
          AND rt.expiresAt > :now
    """)
    long countActiveTokens(@Param("userId") Long userId, @Param("now") Instant now);
}
