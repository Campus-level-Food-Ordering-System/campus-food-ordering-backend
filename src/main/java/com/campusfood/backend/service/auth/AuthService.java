package com.campusfood.backend.service.auth;

import com.campusfood.backend.dto.auth.*;
import com.campusfood.backend.entity.auth.User;
import com.campusfood.backend.enums.AuthType;
import com.campusfood.backend.enums.Role;
import com.campusfood.backend.exception.auth.EmailAlreadyExistsException;
import com.campusfood.backend.exception.auth.InvalidCredentialsException;
import com.campusfood.backend.repository.auth.UserRepository;
import com.campusfood.backend.security.CustomUserDetails;
import com.campusfood.backend.security.jwt.JwtService;
import com.campusfood.backend.service.EmailService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;

/**
 * AuthService handles all authentication business logic
 * 
 * MAIN RESPONSIBILITIES:
 * 1. SIGNUP: create user account + send verification email
 * 2. EMAIL VERIFY: confirm user email ownership
 * 3. RESEND CODE: regenerate verification code
 * 4. SIGNIN: authenticate user + generate tokens
 * 5. FORGOT PASSWORD: initiate password reset flow
 * 6. RESET PASSWORD: update password + revoke all sessions
 * 7. USER LISTING: admin endpoint
 * 
 * SECURITY FEATURES:
 * - Bcrypt password hashing
 * - Email verification required before signin
 * - Verification code expiry (15 minutes)
 * - Password reset code expiry (1 hour)
 * - Session revocation on password change (force re-login)
 * - Stateless JWT authentication
 */
@Slf4j
@Service
@RequiredArgsConstructor
@Transactional
public class AuthService {

    private final UserRepository userRepository;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final EmailService emailService;
    private final PasswordEncoder passwordEncoder;
    private final RefreshTokenService refreshTokenService;

    // === CONSTANTS ===
    private static final int VERIFICATION_CODE_EXPIRY_MINUTES = 15;
    private static final int PASSWORD_RESET_CODE_EXPIRY_MINUTES = 60;

    // ============================================
    // 1. SIGNUP
    // ============================================

    /**
     * SIGNUP endpoint
     * Create new user account and send email verification code
     * 
     * FLOW:
     * 1. Check email not already registered
     * 2. Hash password with Bcrypt
     * 3. Generate 6-digit verification code
     * 4. Save user to DB
     * 5. Send email verification code
     * 6. Return user info (NO tokens yet)
     * 
     * User cannot signin until email is verified
     * 
     * @param request signup request with email, password, role
     * @return user details (id, email, role, etc.)
     * @throws EmailAlreadyExistsException if email already registered
     */
    public SignupResponseDTO signup(SignupRequestDTO request) {
        log.info("Signup request for email: {}", request.getEmail());

        // 1. Check email not already registered
        if (userRepository.existsByEmail(request.getEmail())) {
            log.warn("Signup failed: email already exists: {}", request.getEmail());
            throw new EmailAlreadyExistsException();
        }

        // 2. Parse role and auth type from enum (not string parsing)
        Role role = request.getRole();  // Assuming DTO accepts Role enum
        AuthType authType = request.getAuthType();  // Assuming DTO accepts AuthType enum

        // 3. Create user entity
        User user = User.builder()
                .username(request.getUsername())
                .email(request.getEmail())
                .password(authType == AuthType.PASSWORD
                        ? passwordEncoder.encode(request.getPassword())
                        : null
                )
                .role(role)
                .authType(authType)
                .collegeName(request.getCollegeName())
                .department(request.getDepartment())
                .yearOfStudy(request.getYearOfStudy())
                .emailVerified(false)
                .build();

        // 4. Generate verification code
        String verificationCode = generateVerificationCode();
        user.setVerificationCode(verificationCode);
        user.setVerificationCodeExpiresAt(
                Instant.now().plusSeconds(VERIFICATION_CODE_EXPIRY_MINUTES * 60)
        );

        // 5. Save to DB
        User savedUser = userRepository.save(user);
        log.info("User created with ID: {}", savedUser.getId());

        // 6. Send verification email
        emailService.sendVerificationEmail(user.getEmail(), verificationCode);
        log.info("Verification email sent to: {}", user.getEmail());

        // 7. Return response
        return SignupResponseDTO.builder()
                .id(savedUser.getId())
                .username(savedUser.getUsername())
                .email(savedUser.getEmail())
                .role(savedUser.getRole())
                .emailVerified(savedUser.isEmailVerified())
                .build();
    }

    // ============================================
    // 2. EMAIL VERIFICATION
    // ============================================

    /**
     * VERIFY EMAIL endpoint
     * Confirm user email ownership using verification code
     * 
     * FLOW:
     * 1. Find user by email
     * 2. Validate verification code not expired
     * 3. Validate code matches
     * 4. Mark email as verified
     * 5. Clear verification code and expiry
     * 6. Save user
     * 
     * After verification, user can signin
     * 
     * @param email user's email
     * @param code 6-digit verification code
     * @throws IllegalArgumentException if user not found or code invalid
     * @throws IllegalStateException if email already verified or code expired
     */
    public void verifyEmail(String email, String code) {
        log.info("Email verification request for: {}", email);

        // 1. Find user
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> {
                    log.warn("User not found: {}", email);
                    return new IllegalArgumentException("User not found");
                });

        // 2. Check if already verified
        if (user.isEmailVerified()) {
            log.info("Email already verified: {}", email);
            throw new IllegalStateException("Email already verified");
        }

        // 3. Check code expiry
        if (user.getVerificationCodeExpiresAt().isBefore(Instant.now())) {
            log.warn("Verification code expired for: {}", email);
            throw new IllegalStateException("Verification code expired. Request a new one.");
        }

        // 4. Validate code
        if (!user.getVerificationCode().equals(code)) {
            log.warn("Invalid verification code for: {}", email);
            throw new IllegalArgumentException("Invalid verification code");
        }

        // 5. Mark verified and clear code
        user.setEmailVerified(true);
        user.setVerificationCode(null);
        user.setVerificationCodeExpiresAt(null);
        userRepository.save(user);

        log.info("Email verified successfully: {}", email);
    }

    /**
     * RESEND VERIFICATION CODE endpoint
     * Generate new verification code and send email
     * 
     * Triggered when user didn't receive first code or code expired
     * 
     * @param email user's email
     * @throws IllegalArgumentException if user not found
     */
    public void resendVerificationCode(String email) {
        log.info("Resend verification code request for: {}", email);

        // 1. Find user
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> {
                    log.warn("User not found: {}", email);
                    return new IllegalArgumentException("User not found");
                });

        // 2. Check if already verified
        if (user.isEmailVerified()) {
            throw new IllegalStateException("Email already verified");
        }

        // 3. Generate new code
        String newCode = generateVerificationCode();
        user.setVerificationCode(newCode);
        user.setVerificationCodeExpiresAt(
                Instant.now().plusSeconds(VERIFICATION_CODE_EXPIRY_MINUTES * 60)
        );
        userRepository.save(user);

        // 4. Send email
        emailService.sendVerificationEmail(email, newCode);
        log.info("Verification code resent to: {}", email);
    }

    // ============================================
    // 3. SIGNIN
    // ============================================

    /**
     * SIGNIN endpoint
     * Authenticate user and generate JWT tokens
     * 
     * REQUIREMENTS:
     * - Email must exist
     * - Password must match (bcrypt verified)
     * - Email must be verified
     * 
     * FLOW:
     * 1. Authenticate using Spring Security
     * 2. Get user from authentication
     * 3. Generate access token (15 min)
     * 4. Generate refresh token (7 days, hashed)
     * 5. Save refresh token to DB
     * 6. Return access token + user info
     * 7. Controller sets refresh token in HttpOnly cookie
     * 
     * @param request signin request with email + password
     * @return user info + access token
     * @throws InvalidCredentialsException if email/password invalid
     * @throws IllegalStateException if email not verified
     */
    public SigninResponseDTO signin(SigninRequestDTO request) {
        log.info("Signin request for email: {}", request.getEmail());

        // 1. Authenticate user (email + password)
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getEmail(),
                            request.getPassword()
                    )
            );

            CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();
            User user = userDetails.getUser();

            // 2. Check email verified
            if (!user.isEmailVerified()) {
                log.warn("Signin attempt with unverified email: {}", request.getEmail());
                throw new IllegalStateException("Email not verified. Check your inbox.");
            }

            log.info("User authenticated: {} (ID: {})", user.getEmail(), user.getId());

            // 3. Generate tokens
            String accessToken = jwtService.generateAccessToken(userDetails);
            String deviceId = generateDeviceId();
            String refreshToken = refreshTokenService.createRefreshToken(userDetails, deviceId);

            log.info("Tokens generated for user: {}", user.getId());

            // 4. Return response
            return SigninResponseDTO.builder()
                    .id(user.getId())
                    .username(user.getUsername())
                    .email(user.getEmail())
                    .role(user.getRole())
                    .accessToken(accessToken)
                    .tokenType("Bearer")
                    .expiresIn(900) // 15 minutes
                    .build();

        } catch (org.springframework.security.core.AuthenticationException e) {
            log.warn("Authentication failed for email: {}", request.getEmail());
            throw new InvalidCredentialsException("Invalid email or password");
        }
    }

    // ============================================
    // 4. PASSWORD RESET
    // ============================================

    /**
     * FORGOT PASSWORD endpoint
     * Initiate password reset flow
     * 
     * FLOW:
     * 1. Find user by email
     * 2. Generate reset code
     * 3. Save reset code and expiry to DB
     * 4. Send reset email
     * 
     * @param request contains email
     * @throws IllegalArgumentException if user not found
     */
    public void forgotPassword(ForgotPasswordRequestDTO request) {
        log.info("Forgot password request for: {}", request.getEmail());

        // 1. Find user
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> {
                    log.warn("User not found for password reset: {}", request.getEmail());
                    // Don't reveal if email exists (security)
                    return new IllegalArgumentException("If email exists, reset code will be sent");
                });

        // 2. Generate reset code
        String resetCode = generateVerificationCode();
        user.setPasswordResetCode(resetCode);
        user.setPasswordResetCodeExpiresAt(
                Instant.now().plusSeconds(PASSWORD_RESET_CODE_EXPIRY_MINUTES * 60)
        );
        userRepository.save(user);

        log.info("Password reset code generated for user: {}", user.getId());

        // 3. Send email
        emailService.sendPasswordResetEmail(user.getEmail(), resetCode);
        log.info("Password reset email sent to: {}", user.getEmail());
    }

    /**
     * RESET PASSWORD endpoint
     * Update password with reset code
     * 
     * REQUIREMENTS:
     * - Reset code must be valid and not expired
     * - Triggers session revocation (user logged out from all devices)
     * 
     * FLOW:
     * 1. Find user by email
     * 2. Validate reset code
     * 3. Check code not expired
     * 4. Update password
     * 5. Clear reset code
     * 6. Revoke all refresh tokens (force re-login)
     * 7. Save user
     * 
     * @param request contains email, reset code, new password
     * @throws IllegalArgumentException if user not found or code invalid
     * @throws IllegalStateException if code expired
     */
    public void resetPassword(ResetPasswordRequestDTO request) {
        log.info("Reset password request for: {}", request.getEmail());

        // 1. Find user
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        // 2. Validate reset code
        if (user.getPasswordResetCode() == null || !user.getPasswordResetCode().equals(request.getResetCode())) {
            log.warn("Invalid reset code for user: {}", user.getId());
            throw new IllegalArgumentException("Invalid reset code");
        }

        // 3. Check expiry
        if (user.getPasswordResetCodeExpiresAt().isBefore(Instant.now())) {
            log.warn("Password reset code expired for user: {}", user.getId());
            throw new IllegalStateException("Reset code expired. Request a new one.");
        }

        // 4. Update password
        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        user.setPasswordResetCode(null);
        user.setPasswordResetCodeExpiresAt(null);
        userRepository.save(user);

        log.info("Password updated for user: {}", user.getId());

        // 5. Revoke all tokens (security measure + force re-login)
        refreshTokenService.revokeAllTokensForUser(user.getId());
        log.info("All refresh tokens revoked for user: {} (password reset)", user.getId());
    }

    // ============================================
    // 5. USER LISTING (ADMIN)
    // ============================================

    /**
     * List all users
     * ADMIN ONLY endpoint
     * 
     * @return all users in system
     */
    public List<User> getAllUsers() {
        return userRepository.findAll();
    }

    // ============================================
    // HELPER METHODS
    // ============================================

    /**
     * Generate 6-digit verification code
     * Used for email verification and password reset
     * 
     * @return random 6-digit code (100000-999999)
     */
    private String generateVerificationCode() {
        return String.valueOf(new java.security.SecureRandom().nextInt(900000) + 100000);
    }

    /**
     * Generate device ID for tracking sessions
     * Can be overridden by client to use actual device ID
     * 
     * @return device identifier
     */
    private String generateDeviceId() {
        return "device_" + System.currentTimeMillis();
    }
}
