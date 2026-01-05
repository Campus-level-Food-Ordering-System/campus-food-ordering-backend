package com.campusfood.backend.repository.auth;

import com.campusfood.backend.entity.auth.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * Repository for User entity.
 * 
 * Custom queries:
 * - findByEmail: used for signin and email verification
 * - existsByEmail: used in signup validation
 */
@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    /**
     * Find user by email
     * Used in signin, email verification, and password reset flows
     * 
     * @param email user's email
     * @return Optional containing user if found
     */
    Optional<User> findByEmail(String email);

    /**
     * Find user by username
     * Can be used for additional authentication methods
     * 
     * @param username user's username
     * @return Optional containing user if found
     */
    Optional<User> findByUsername(String username);

    /**
     * Check if user with email already exists
     * Used during signup to prevent duplicate registrations
     * 
     * @param email email to check
     * @return true if email exists, false otherwise
     */
    boolean existsByEmail(String email);

    /**
     * Check if user with username already exists
     * 
     * @param username username to check
     * @return true if username exists, false otherwise
     */
    boolean existsByUsername(String username);
}
