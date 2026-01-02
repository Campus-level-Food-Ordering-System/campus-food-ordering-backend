
package com.campusfood.backend.controller;

import java.util.List;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.campusfood.backend.dto.auth.ResendCodeRequestDTO;
import com.campusfood.backend.dto.auth.SigninRequestDTO;
import com.campusfood.backend.dto.auth.SigninResponseDTO;
import com.campusfood.backend.dto.auth.SignupRequestDTO;
import com.campusfood.backend.dto.auth.SignupResponseDTO;
import com.campusfood.backend.dto.auth.VerifyEmailRequestDTO;
import com.campusfood.backend.entity.User;
import com.campusfood.backend.service.AuthService;
import com.campusfood.backend.utils.ApiResponse;

import jakarta.validation.Valid;

@RestController
@RequestMapping("api/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/signup")
    public ApiResponse<SignupResponseDTO> signup(
            @Valid @RequestBody SignupRequestDTO request) {

        SignupResponseDTO response = authService.signup(request);

        return ApiResponse.of("User signed up successfully", 201, response);
    }

    @PostMapping("/signin")
    public ApiResponse<SigninResponseDTO> signin(
            @Valid @RequestBody SigninRequestDTO request) {

        SigninResponseDTO response = authService.signin(request);

        return ApiResponse.of("User signed in successfully", 200, response);
    }

    @PostMapping("/verify-email")
    public ApiResponse<Void> verifyEmail(
            @Valid @RequestBody VerifyEmailRequestDTO request) {

        authService.verifyEmail(request.getEmail(), request.getCode());

        return ApiResponse.of("Email verified successfully", 200, null);
    }

    @PostMapping("/resend-verification-code")
    public ApiResponse<Void> resendVerificationCode(
            @Valid @RequestBody ResendCodeRequestDTO request) {

        authService.resendVerificationCode(request.getEmail());

        return ApiResponse.of("Verification code sent successfully", 200, null);
    }

    // TEMP
    @GetMapping("/users")
    public ApiResponse<List<User>> getAllUsers() {
        return ApiResponse.of(
                "Users fetched successfully",
                200,
                authService.getAllUsers());
    }
}
