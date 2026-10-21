package com.utch.backendauth.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * Binds jwt.* properties from application.yml into this bean.
 */
@Configuration
@ConfigurationProperties(prefix = "jwt")
public class JwtConfig {

    /** HS256 secret key — at least 256 bits (32 chars) for JJWT 0.12.x. */
    private String secret;

    /** Token lifetime in milliseconds (default: 1 hour). */
    private long expirationMs = 3_600_000L;

    // --- getters / setters ---

    public String getSecret() {
        return secret;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }

    public long getExpirationMs() {
        return expirationMs;
    }

    public void setExpirationMs(long expirationMs) {
        this.expirationMs = expirationMs;
    }
}
