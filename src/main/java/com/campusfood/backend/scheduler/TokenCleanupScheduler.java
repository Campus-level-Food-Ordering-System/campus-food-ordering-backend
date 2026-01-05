package com.campusfood.backend.scheduler;

import com.campusfood.backend.repository.auth.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Instant;

/**
 * Scheduled cleanup job for refresh tokens
 * 
 * PURPOSE:
 * Delete expired and revoked refresh tokens from database
 * Keeps database clean and improves query performance
 * 
 * SCHEDULE: Every hour at the start of the hour
 * 
 * WHY NEEDED:
 * - Expired tokens are no longer valid but still in DB
 * - Revoked tokens (rotated or logged out) clutter DB
 * - Without cleanup, DB grows unbounded
 * - Cleanup is asynchronous (doesn't block requests)
 * 
 * PERFORMANCE:
 * - Runs at low traffic time (configurable)
 * - Uses database-level deletion (not iterating in Java)
 * - Minimal impact on application performance
 */
@Slf4j
@Component
@EnableScheduling
@RequiredArgsConstructor
public class TokenCleanupScheduler {

    private final RefreshTokenRepository refreshTokenRepository;

    /**
     * Delete expired and revoked refresh tokens
     * 
     * Runs every hour (cron: 0 0 * * * * = start of every hour)
     * 
     * Deletes:
     * 1. Revoked tokens (user logged out or token rotated)
     * 2. Expired tokens (expiresAt < now)
     */
    @Scheduled(cron = "0 0 * * * *") // Every hour
    public void cleanupExpiredTokens() {
        log.info("Starting scheduled refresh token cleanup...");
        try {
            Instant now = Instant.now();
            refreshTokenRepository.deleteRevokedOrExpired(now);
            log.info("Refresh token cleanup completed successfully");
        } catch (Exception e) {
            log.error("Error during refresh token cleanup", e);
            // Continue silently - don't break application if cleanup fails
        }
    }

    /**
     * Alternative cleanup job (runs every 30 minutes)
     * Uncomment if you want more frequent cleanup
     */
    // @Scheduled(fixedRate = 1800000) // Every 30 minutes (in milliseconds)
    // public void cleanupExpiredTokensFixed() {
    //     cleanupExpiredTokens();
    // }
}
