package com.campusfood.backend.dto.auth;

import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
@Getter
public class RefreshTokenResult {
    private RefreshTokenResponseDTO response;
    private String refreshToken;
}
