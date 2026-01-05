package com.campusfood.backend.exception.auth;

/**
 * Exception thrown when refresh token is revoked or compromised
 * 
 * Raised when:
 * - Refresh token use is attempted after being revoked
 * - Token reuse is detected (same token used twice = security breach)
 */
public class TokenRevokedException extends RuntimeException {
    
    public TokenRevokedException() {
        super("Refresh token has been revoked. Please login again.");
    }

    public TokenRevokedException(String message) {
        super(message);
    }
}
