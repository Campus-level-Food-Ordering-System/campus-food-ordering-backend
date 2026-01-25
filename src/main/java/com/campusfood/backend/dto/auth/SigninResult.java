package com.campusfood.backend.dto.auth;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class SigninResult {
    private SigninResponseDTO response;
    private String refreshToken;
}
