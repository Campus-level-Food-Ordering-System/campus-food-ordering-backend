package com.campusfood.backend.exception;

import org.springframework.http.HttpStatus;

/**
 * Base class for ALL business exceptions.
 * Business exceptions = expected domain errors.
 */
public abstract class BusinessException extends RuntimeException {

    private final HttpStatus status;

    protected BusinessException(String message, HttpStatus status) {
        super(message);
        this.status = status;
    }

    public HttpStatus getStatus() {
        return status;
    }
}
