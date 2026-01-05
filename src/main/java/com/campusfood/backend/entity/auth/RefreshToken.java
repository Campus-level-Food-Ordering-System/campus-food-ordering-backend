package com.campusfood.backend.entity.auth;

import com.campusfood.backend.entity.auth.User;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;

import java.time.Instant;

/**
 * RefreshToken entity for JWT token rotation.
 * 
 * SECURITY FEATURES:
 * 1. Only tokenHash is stored in DB (actual token sent to client only once)
 * 2. Each device can have its own refresh token (multiple concurrent sessions)
 * 3. Token rotation on every refresh request (old token is revoked)
 * 4. If a revoked token is reused → revoke ALL tokens for that user (security breach)
 * 5. Automatic cleanup of expired/revoked tokens (scheduled job)
 * 
 * Flow:
 * 1. User signs in → new RefreshToken created, revoked=false
 * 2. User requests /refresh → old token revoked, new token created
 * 3. If user tries to use revoked token → revoke ALL tokens, force re-login
 * 4. Expired tokens auto-deleted by scheduler every hour
 */
@Entity
@Table(name = "refresh_tokens", indexes = {
    @Index(name = "idx_user_id", columnList = "user_id"),
    @Index(name = "idx_token_hash", columnList = "token_hash"),
    @Index(name = "idx_revoked_expires_at", columnList = "revoked,expires_at")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@JsonIgnoreProperties({"hibernateLazyInitializer", "handler"})
public class RefreshToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /**
     * User who owns this refresh token
     * LAZY loaded to avoid N+1 queries
     */
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    @JsonIgnore
    private User user;

    /**
     * SHA256 hash of the actual refresh token
     * 
     * WHY HASHED:
     * - Database breach doesn't expose actual tokens
     * - Similar to password hashing
     * - Token verification: hash received token and compare with DB
     * 
     * UNIQUE: prevents storing same token twice
     */
    @Column(name = "token_hash", nullable = false, unique = true)
    private String tokenHash;

    /**
     * Device identifier (mobile device ID, browser fingerprint, etc.)
     * Allows multiple active sessions per user
     * Used in logout flow to revoke only one device's token
     */
    @Column(name = "device_id", nullable = true)
    private String deviceId;

    /**
     * Token expiration timestamp
     * Used in cleanup job to delete expired tokens
     * Tokens are still valid 1-2 seconds after expiry during clock skew
     */
    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    /**
     * Revocation status
     * - false: active, can be used for refresh
     * - true: revoked (either explicitly or during rotation), cannot be used
     */
    @Column(nullable = false, columnDefinition = "boolean default false")
    @Builder.Default
    private boolean revoked = false;

    /**
     * Token creation timestamp
     */
    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;
}
