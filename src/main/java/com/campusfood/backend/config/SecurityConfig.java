package com.campusfood.backend.config;

import com.campusfood.backend.security.jwt.JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;

import java.util.Arrays;

/**
 * Spring Security Configuration
 * 
 * SECURITY ARCHITECTURE:
 * 1. Stateless JWT authentication (no sessions)
 * 2. All auth endpoints are PUBLIC (/api/auth/*)
 * 3. All other endpoints require valid JWT token
 * 4. Custom JWT filter validates access tokens
 * 5. CORS enabled for frontend communication
 * 
 * AUTHENTICATION FLOW:
 * 1. User signs in → receives access token (+ refresh token in cookie)
 * 2. User sends access token in Authorization header for API requests
 * 3. JwtAuthenticationFilter validates token and loads user
 * 4. User authorized based on role
 * 5. When access token expires → call /refresh endpoint
 * 
 * TOKEN EXPIRY:
 * - Access token: 15 minutes (short-lived)
 * - Refresh token: 7 days (long-lived, in httpOnly cookie)
 */
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final UserDetailsService userDetailsService;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    /**
     * PUBLIC AUTH ENDPOINTS
     * These endpoints are accessible without authentication
     */
    private static final String[] PUBLIC_ENDPOINTS = {
            "/api/auth/**",  // All auth endpoints
            "/swagger-ui/**",  // Swagger UI
            "/v3/api-docs/**",  // OpenAPI docs
            "/health"  // Health check
    };

    /**
     * Security Filter Chain
     * Configures HTTP security, CORS, session management, and authentication
     * 
     * @param http HTTP security builder
     * @return security filter chain
     * @throws Exception if configuration fails
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                // 1. CSRF: Disable (stateless JWT doesn't need CSRF protection)
                .csrf(csrf -> csrf.disable())

                // 2. CORS: Enable for frontend communication
                .cors(cors -> cors.configurationSource(request -> {
                    CorsConfiguration config = new CorsConfiguration();
                    config.setAllowedOrigins(Arrays.asList("http://localhost:3000", "http://localhost:5173"));
                    config.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
                    config.setAllowedHeaders(Arrays.asList("*"));
                    config.setAllowCredentials(true);
                    config.setMaxAge(3600L);
                    return config;
                }))

                // 3. SESSION: Stateless (JWT tokens, no server sessions)
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )

                // 4. AUTHORIZATION: Define access rules
                .authorizeHttpRequests(auth -> auth
                        // Public endpoints (no auth required)
                        .requestMatchers(PUBLIC_ENDPOINTS).permitAll()
                        // All other endpoints require authentication
                        .anyRequest().authenticated()
                )

                // 5. AUTHENTICATION PROVIDER
                .authenticationProvider(authenticationProvider())

                // 6. JWT FILTER: Run before UsernamePasswordAuthenticationFilter
                // This validates JWT tokens in Authorization header
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    /**
     * Authentication Provider
     * Uses custom UserDetailsService to load users from database
     * Uses BCryptPasswordEncoder to validate passwords
     * 
     * @return authentication provider
     */
    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder());
        return provider;
    }

    /**
     * Authentication Manager
     * Used in controllers to authenticate user (signin)
     * 
     * @param config authentication configuration
     * @return authentication manager
     * @throws Exception if configuration fails
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    /**
     * Password Encoder
     * BCrypt with strength 10 (2^10 iterations)
     * Takes ~100ms to hash a password (slow on purpose for security)
     * 
     * @return BCrypt password encoder
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(10);
    }
}

