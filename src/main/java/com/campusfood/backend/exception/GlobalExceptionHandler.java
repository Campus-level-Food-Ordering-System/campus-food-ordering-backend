package com.campusfood.backend.exception;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import com.campusfood.backend.utils.ApiError;

import tools.jackson.databind.exc.InvalidFormatException;

@RestControllerAdvice
public class GlobalExceptionHandler {

    // =========================
    // 1. VALIDATION ERRORS
    // =========================
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiError> handleValidationErrors(
            MethodArgumentNotValidException ex) {

        Map<String, String> fieldErrors = new HashMap<>();

        ex.getBindingResult()
          .getFieldErrors()
          .forEach(error ->
              fieldErrors.put(
                  error.getField(),
                  error.getDefaultMessage()
              )
          );

        ApiError apiError = new ApiError(
                "Validation failed",
                HttpStatus.BAD_REQUEST.value(),
                fieldErrors
        );

        return ResponseEntity
                .badRequest()
                .body(apiError);
    }

    // =========================
    // 2. BUSINESS EXCEPTIONS (ALL)
    // =========================
    @ExceptionHandler(BusinessException.class)
    public ResponseEntity<ApiError> handleBusinessExceptions(
            BusinessException ex) {

        ApiError apiError = new ApiError(
                ex.getMessage(),
                ex.getStatus().value(),
                null
        );

        return ResponseEntity
                .status(ex.getStatus())
                .body(apiError);
    }

    // =========================
    // 3. FALLBACK (UNEXPECTED)
    // =========================
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiError> handleAllExceptions(Exception ex) {

        ApiError error = new ApiError(
                ex.getMessage() != null ? ex.getMessage() : "Internal Server Error",
                HttpStatus.INTERNAL_SERVER_ERROR.value(),
                null
        );

        return ResponseEntity
                .status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(error);
    }

    // =========================
    // 4. ENUM ERRORS
    // =========================
    @ExceptionHandler(HttpMessageNotReadableException.class)
public ResponseEntity<ApiError> handleJsonError(HttpMessageNotReadableException ex) {
    if (ex.getCause() instanceof InvalidFormatException ife && ife.getTargetType().isEnum()) {
        
        // getPathReference() returns the field path as a String (e.g., "role")
        String path = ife.getPathReference(); 
        // Clean up the path string if it contains class names
        String fieldName = path.contains("[") ? path.substring(path.lastIndexOf("[\"") + 2, path.lastIndexOf("\"]")) : path;
        
        String options = Arrays.toString(ife.getTargetType().getEnumConstants());
        
        return ResponseEntity.badRequest().body(new ApiError(
            "Invalid value for field: " + fieldName + ". Must be one of: " + options, 
            400, 
            null));
    }
    return ResponseEntity.badRequest().body(new ApiError("Malformed JSON", 400, null));
}
}


