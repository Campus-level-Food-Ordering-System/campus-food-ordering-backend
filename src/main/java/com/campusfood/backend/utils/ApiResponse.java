package com.campusfood.backend.utils;

import com.fasterxml.jackson.annotation.JsonPropertyOrder;

import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@JsonPropertyOrder({ "message", "status", "data" })
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class ApiResponse<T> {

    private String message;
    private Integer status;
    private T data;

    public static <T> ApiResponse<T> of(String message, Integer status, T data) {
        return new ApiResponse<>(message, status, data);
    }
}
