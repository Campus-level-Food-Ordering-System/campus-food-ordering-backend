package com.campusfood.backend.dto.auth;

import com.campusfood.backend.enums.AuthType;
import com.campusfood.backend.enums.Role;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;


import jakarta.persistence.Column;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;


public class SignupDTO {

    public static class SignupRequest {

        @NotBlank(message = "Username is required")
        private String username;

        @NotBlank(message = "Email is required")
        @Email(message = "Invalid email")
        private String email;


       @Enumerated(EnumType.STRING)
       @Column(nullable = false)
       private Role role;


        @NotBlank(message = "Password is required")
        @Size(min = 6, message = "Password must be at least 6 characters")
        private String password;

        @NotBlank(message = "College name is required")
        @Pattern(
         regexp = "^[A-Za-z ]+$",
         message = "College name must contain only letters"
         )
        private String collegeName;

        @NotBlank(message = "Department is required")
        private String department;

        @NotBlank(message = "Year of study is required")
        private String yearOfStudy;

        private AuthType authType;

        public String getUsername() {
            return username;
        }
        public void setUsername(String username) {
            this.username = username;
        }

        public String getEmail() {
            return email;
        }
        public void setEmail(String email) {
            this.email = email;
        }

        public String getPassword() {
            return password;
        }
        public void setPassword(String password) {
            this.password = password;
        }

        public String getCollegeName() {
            return collegeName;
        }
        public void setCollegeName(String collegeName) {
            this.collegeName = collegeName;
        }

        public String getDepartment() {
            return department;
        }
        public void setDepartment(String department) {
            this.department = department;
        }

        public String getYearOfStudy() {
            return yearOfStudy;
        }
        public void setYearOfStudy(String yearOfStudy) {
            this.yearOfStudy = yearOfStudy;
        }

        public AuthType getAuthType() {
            return authType;
        }
        public void setAuthType(AuthType authType) {
            this.authType = authType;
        }

        public void setRole(Role role) {

            this.role = role;
        }

        public Role getRole() {
            return role;
        }
        
    }

    public static class SignupResponse {

        private Long id;
        private String username;
        private String email;
        private Role role;
        private boolean emailVerified;

        public SignupResponse(
                Long id,
                String username,
                String email,
                Role role,
                boolean emailVerified
        ) {
            this.id = id;
            this.username = username;
            this.email = email;
            this.role = role;
            this.emailVerified = emailVerified;
        }

        // getters
        public Long getId() {
            return id;
        }

        public String getUsername() {
            return username;
        }

        public String getEmail() {
            return email;
        }

        public Role getRole() {
            return role;
        }

        public boolean isEmailVerified() {
            return emailVerified;
        }
    }
}
