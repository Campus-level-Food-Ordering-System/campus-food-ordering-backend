package com.campusfood.backend.exception.auth;

/**
 * Exception thrown when JWT token is expired
 * Raised when trying to use an expired access token
 */
public class TokenExpiredException extends RuntimeException {
    
    public TokenExpiredException() {
        super("Token has expired");
    }

    public TokenExpiredException(String message) {
        super(message);
    }
}
