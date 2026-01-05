package com.campusfood.backend.security.jwt;

import com.campusfood.backend.entity.auth.User;
import com.campusfood.backend.exception.auth.InvalidTokenException;
import com.campusfood.backend.exception.auth.TokenExpiredException;
import com.campusfood.backend.repository.auth.UserRepository;
import com.campusfood.backend.security.CustomUserDetails;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * JWT Authentication Filter
 * 
 * Runs on every HTTP request to validate JWT access tokens
 * 
 * FLOW:
 * 1. Extract token from Authorization header
 * 2. Validate token signature and expiration
 * 3. Extract user ID from token
 * 4. Load user from database
 * 5. Set authentication in SecurityContext
 * 6. Allow request to proceed
 * 
 * If token is invalid/expired:
 * - Log warning and continue (request will be rejected by @PreAuthorize if needed)
 * - User can call /refresh endpoint to get new access token
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserRepository userRepository;

    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";

    /**
     * Filter method called for every HTTP request
     * 
     * @param request HTTP request
     * @param response HTTP response
     * @param filterChain filter chain
     * @throws ServletException if servlet error occurs
     * @throws IOException if IO error occurs
     */
    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {

        try {
            // 1. Extract token from Authorization header
            String token = extractToken(request);

            if (token != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                // 2. Validate token
                if (jwtService.validateToken(token)) {
                    // 3. Extract user ID
                    Long userId = jwtService.extractUserId(token);

                    // 4. Load user from database
                    User user = userRepository.findById(userId)
                            .orElseThrow(() -> {
                                log.warn("User not found with ID: {}", userId);
                                return new IllegalArgumentException("User not found");
                            });

                    // 5. Create authentication object
                    CustomUserDetails userDetails = new CustomUserDetails(user);
                    UsernamePasswordAuthenticationToken authentication =
                            new UsernamePasswordAuthenticationToken(
                                    userDetails,
                                    null,
                                    userDetails.getAuthorities()
                            );
                    authentication.setDetails(
                            new WebAuthenticationDetailsSource().buildDetails(request)
                    );

                    // 6. Set authentication in SecurityContext
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                    log.debug("JWT authentication set for user: {}", user.getEmail());
                }
            }
        } catch (TokenExpiredException e) {
            log.warn("Token expired: {}", e.getMessage());
            // Continue without authentication (user can refresh token)
        } catch (InvalidTokenException e) {
            log.warn("Invalid token: {}", e.getMessage());
            // Continue without authentication
        } catch (Exception e) {
            log.error("Error processing JWT: {}", e.getMessage());
            // Continue without authentication
        }

        // 7. Continue filter chain
        filterChain.doFilter(request, response);
    }

    /**
     * Extract JWT token from Authorization header
     * 
     * Expected format: Authorization: Bearer <token>
     * 
     * @param request HTTP request
     * @return token if found, null otherwise
     */
    private String extractToken(HttpServletRequest request) {
        String authHeader = request.getHeader(AUTHORIZATION_HEADER);

        if (authHeader != null && authHeader.startsWith(BEARER_PREFIX)) {
            String token = authHeader.substring(BEARER_PREFIX.length()).trim();

            log.debug("Extracted JWT token from header", token);
            // Return null if token is empty

            return token.isEmpty() ? null : token;
        }

        return null;
    }
}
