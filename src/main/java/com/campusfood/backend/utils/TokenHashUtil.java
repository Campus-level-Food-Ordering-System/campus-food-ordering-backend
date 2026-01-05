package com.campusfood.backend.utils;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Utility class for hashing refresh tokens
 * 
 * WHY HASH TOKENS:
 * - Database breaches don't expose actual tokens
 * - Similar to password hashing
 * - On token use, hash received token and compare with DB hash
 * - Attacker needs both DB access AND the token itself (defense in depth)
 * 
 * ALGORITHM: SHA256 (same as password hashing)
 */
public class TokenHashUtil {

    /**
     * Hash a token using SHA256
     * 
     * @param token plain text token
     * @return SHA256 hash of token (hex encoded)
     * @throws RuntimeException if SHA256 algorithm is not available
     */
    public static String sha256(String token) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(token.getBytes());
            StringBuilder hexString = new StringBuilder();

            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }

            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not available", e);
        }
    }
}
