package com.campusfood.backend.service;

import java.util.List;
import java.util.UUID;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.campusfood.backend.dto.auth.SignupRequestDTO;
import com.campusfood.backend.dto.auth.SignupResponseDTO;
import com.campusfood.backend.entity.User;
import com.campusfood.backend.enums.AuthType;
import com.campusfood.backend.enums.Role;
import com.campusfood.backend.exception.auth.EmailAlreadyExistsException;
import com.campusfood.backend.repository.AuthRepository;

@Service
public class AuthService {

    private final AuthRepository authRepository;
    private final PasswordEncoder passwordEncoder;

    public AuthService(AuthRepository authRepository,
            PasswordEncoder passwordEncoder) {
        this.authRepository = authRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public SignupResponseDTO signup(SignupRequestDTO request) {

        // 1️⃣ Check if email already exists
        if (authRepository.existsByEmail(request.getEmail())) {
            throw new EmailAlreadyExistsException();
        }

        // 2️⃣ Validate role-specific fields
        if (request.getRole() == Role.USER) {
            if (request.getCollegeName() == null ||
                    request.getDepartment() == null ||
                    request.getYearOfStudy() == null) {
                throw new IllegalArgumentException("Student details are required for USER role");
            }
        }

        // 3️⃣ Create User entity
        User user = User.builder()
                .username(request.getUsername())
                .email(request.getEmail())
                .password(
                        request.getAuthType() == AuthType.PASSWORD
                                ? passwordEncoder.encode(request.getPassword())
                                : null)

                .role(request.getRole())
                .authType(request.getAuthType())
                .collegeName(request.getCollegeName())
                .department(request.getDepartment())
                .yearOfStudy(request.getYearOfStudy())
                .emailVerified(false)
                .emailVerificationToken(UUID.randomUUID().toString())
                .build();

        // 4️⃣ Save user
        User savedUser = authRepository.save(user);

        // 5️⃣ Return response
        return new SignupResponseDTO(
                savedUser.getId(),
                savedUser.getUsername(),
                savedUser.getEmail(),
                savedUser.getRole(),
                savedUser.isEmailVerified());
    }

    // TEMP: admin-only later
    public List<User> getAllUsers() {
        return authRepository.findAll();
    }
}
