
package com.campusfood.backend.controller;

import java.util.List;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.campusfood.backend.dto.auth.SignupRequestDTO;
import com.campusfood.backend.dto.auth.SignupResponseDTO;
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

    // TEMP
    @GetMapping("/users")
    public ApiResponse<List<User>> getAllUsers() {
        return ApiResponse.of(
                "Users fetched successfully",
                200,
                authService.getAllUsers());
    }
}
