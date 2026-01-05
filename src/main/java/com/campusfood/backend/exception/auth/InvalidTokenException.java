package com.campusfood.backend.exception.auth;

/**
 * Exception thrown when JWT token is invalid
 * Raised when token signature verification fails or token format is invalid
 */
public class InvalidTokenException extends RuntimeException {
    
    public InvalidTokenException() {
        super("Invalid or malformed token");
    }

    public InvalidTokenException(String message) {
        super(message);
    }
}
