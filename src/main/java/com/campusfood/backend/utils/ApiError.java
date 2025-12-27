package com.campusfood.backend.utils;

public class ApiError {

    private String message;
    private Integer status;
    private Object errors;

    public ApiError(String message, Integer status, Object errors) {
        this.message = message;
        this.status = status;
        this.errors = errors;
    }

    public String getMessage() {
        return message;
    }

    public Integer getStatus() {
        return status;
    }

    public Object getErrors() {
        return errors;
    }
}
