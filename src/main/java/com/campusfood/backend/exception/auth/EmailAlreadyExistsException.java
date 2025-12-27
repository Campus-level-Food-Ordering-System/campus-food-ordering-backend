package com.campusfood.backend.exception.auth;

import org.springframework.http.HttpStatus;

import com.campusfood.backend.exception.BusinessException;

public class EmailAlreadyExistsException extends BusinessException {

    public EmailAlreadyExistsException() {
        super("Email already in use", HttpStatus.CONFLICT);
    }
}
