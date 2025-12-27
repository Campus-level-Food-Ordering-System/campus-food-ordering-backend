
package com.campusfood.backend.service;

import java.util.List;

import org.springframework.stereotype.Service;

import com.campusfood.backend.entity.User;
import com.campusfood.backend.repository.AuthRepository;
import com.campusfood.backend.dto.auth.SignupDTO;
import com.campusfood.backend.exception.auth.EmailAlreadyExistsException;



@Service
public class AuthService {

    private final AuthRepository authRepository;

    public AuthService(AuthRepository authRepository) {
        this.authRepository = authRepository;
    }

    public SignupDTO.SignupResponse signup(SignupDTO.SignupRequest request) {

        if (authRepository.existsByEmail(request.getEmail())) {
            throw new EmailAlreadyExistsException();
        }

        User user = new User();
        user.setUsername(request.getUsername());
        user.setEmail(request.getEmail());
        user.setPassword(request.getPassword()); 
        user.setCollegeName(request.getCollegeName());
        user.setDepartment(request.getDepartment());
        user.setYearOfStudy(request.getYearOfStudy());
        user.setAuthType(request.getAuthType());
        user.setRole(request.getRole());
        user.setEmailVerified(false);

        User savedUser = authRepository.save(user);

        return new SignupDTO.SignupResponse(
                savedUser.getId(),
                savedUser.getUsername(),
                savedUser.getEmail(),
                savedUser.getRole(),
                savedUser.isEmailVerified()
        );
    }

    // TEMP: admin-only later
    public List<User> getAllUsers() {
        return authRepository.findAll();
    }
}
