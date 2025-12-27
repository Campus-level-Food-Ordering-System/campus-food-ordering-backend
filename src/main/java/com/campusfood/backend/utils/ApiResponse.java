package com.campusfood.backend.utils;

import com.fasterxml.jackson.annotation.JsonPropertyOrder;

@JsonPropertyOrder({ "message", "status", "data" })
public class ApiResponse<T> {

    private String message;
    private Integer status;
    private T data;

    private ApiResponse(String message, Integer status, T data) {
        this.message = message;
        this.status = status;
        this.data = data;
    }

    public static <T> ApiResponse<T> of(String message, Integer status, T data) {
        return new ApiResponse<>(message, status, data);
    }

    public String getMessage() {
        return message;
    }

    public Integer getStatus() {
        return status;
    }

    public T getData() {
        return data;
    }
}
