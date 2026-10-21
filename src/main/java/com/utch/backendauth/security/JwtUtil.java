package com.utch.backendauth.security;

import com.utch.backendauth.config.JwtConfig;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

/**
 * Utility class for creating and validating JWT tokens using JJWT 0.12.x API.
 *
 * Algorithm: HS256 (HMAC-SHA-256).
 * The secret is read from application.yml via {@link JwtConfig}.
 */
@Component
public class JwtUtil {

    private static final Logger log = LoggerFactory.getLogger(JwtUtil.class);

    private final JwtConfig jwtConfig;

    public JwtUtil(JwtConfig jwtConfig) {
        this.jwtConfig = jwtConfig;
    }

    // -----------------------------------------------------------------
    // Key derivation
    // -----------------------------------------------------------------

    /**
     * Derive a {@link SecretKey} from the configured secret string.
     * JJWT 0.12.x requires the key to be at least 256 bits for HS256.
     */
    private SecretKey signingKey() {
        byte[] keyBytes = jwtConfig.getSecret().getBytes(StandardCharsets.UTF_8);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    // -----------------------------------------------------------------
    // Token generation
    // -----------------------------------------------------------------

    /**
     * Generate a signed JWT for the given {@link UserDetails}.
     *
     * @param userDetails the authenticated user
     * @return compact JWT string
     */
    public String generateToken(UserDetails userDetails) {
        long now = System.currentTimeMillis();

        return Jwts.builder()
                .subject(userDetails.getUsername())
                .issuedAt(new Date(now))
                .expiration(new Date(now + jwtConfig.getExpirationMs()))
                .signWith(signingKey())
                .compact();
    }

    // -----------------------------------------------------------------
    // Token parsing
    // -----------------------------------------------------------------

    /**
     * Parse and return all claims from a JWT.
     * Throws {@link JwtException} if the token is invalid or expired.
     */
    private Claims parseAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(signingKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    /**
     * Extract the subject (username) from a JWT without throwing on validation.
     * Returns {@code null} if the token cannot be parsed.
     */
    public String extractUsername(String token) {
        try {
            return parseAllClaims(token).getSubject();
        } catch (JwtException | IllegalArgumentException e) {
            log.warn("Could not extract username from JWT: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Check whether the token is valid (signature OK, not expired) and
     * belongs to the given {@link UserDetails}.
     */
    public boolean isTokenValid(String token, UserDetails userDetails) {
        try {
            Claims claims = parseAllClaims(token);
            String username = claims.getSubject();
            boolean notExpired = claims.getExpiration().after(new Date());
            return username.equals(userDetails.getUsername()) && notExpired;
        } catch (JwtException | IllegalArgumentException e) {
            log.warn("JWT validation failed: {}", e.getMessage());
            return false;
        }
    }
}
