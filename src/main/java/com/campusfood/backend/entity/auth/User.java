package com.campusfood.backend.entity.auth;

import com.campusfood.backend.enums.AuthType;
import com.campusfood.backend.enums.Role;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.Instant;

/**
 * User entity for authentication and authorization.
 * 
 * Supports two authentication types:
 * - PASSWORD: Traditional email + password authentication
 * - GOOGLE: OAuth2 authentication (password field will be null)
 * 
 * Email verification flow:
 * 1. User signs up → verificationCode is generated
 * 2. User receives verification email
 * 3. User submits verification code → emailVerified = true
 * 
 * Password reset flow:
 * 1. User requests password reset → passwordResetCode is generated
 * 2. User receives reset email
 * 3. User submits reset code + new password → password is updated, all refresh tokens are revoked
 */
@Entity
@Table(name = "users", indexes = {
    @Index(name = "idx_email", columnList = "email"),
    @Index(name = "idx_username", columnList = "username")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String username;

    @Column(nullable = false, unique = true)
    private String email;

    /**
     * Password hash (null if authType is GOOGLE)
     */
    @Column(nullable = true)
    private String password;

    /**
     * User role: ADMIN, USER, VENDOR
     */
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Role role;

    /**
     * Authentication method: PASSWORD or GOOGLE
     */
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private AuthType authType;

    /**
     * Email verification status
     * - false: user just signed up, needs to verify email
     * - true: user verified email, can sign in
     */
    @Column(nullable = false, columnDefinition = "boolean default false")
    @Builder.Default
    private boolean emailVerified = false;

    /**
     * 6-digit verification code for email verification
     * Generated on signup, expires in 15 minutes
     */
    @Column(name = "verification_code")
    private String verificationCode;

    /**
     * Expiration timestamp for verification code
     */
    @Column(name = "verification_code_expires_at")
    private Instant verificationCodeExpiresAt;

    /**
     * Reset code for password recovery
     * Generated on /forgot-password request, expires in 1 hour
     */
    @Column(name = "password_reset_code")
    private String passwordResetCode;

    /**
     * Expiration timestamp for password reset code
     */
    @Column(name = "password_reset_code_expires_at")
    private Instant passwordResetCodeExpiresAt;

    /**
     * User's college/institution name
     */
    @Column(nullable = true)
    private String collegeName;

    /**
     * User's department/major
     */
    @Column(nullable = true)
    private String department;

    /**
     * User's year of study
     */
    @Column(nullable = true)
    private String yearOfStudy;

    /**
     * Account creation timestamp
     */
    @CreationTimestamp
    @Column(nullable = false, updatable = false)
    private Instant createdAt;

    /**
     * Last account update timestamp
     */
    @UpdateTimestamp
    @Column(nullable = false)
    private Instant updatedAt;
}
