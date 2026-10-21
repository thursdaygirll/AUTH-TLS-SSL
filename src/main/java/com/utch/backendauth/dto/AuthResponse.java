package com.utch.backendauth.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Response body returned by /api/auth/login on success.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class AuthResponse {

    private String token;
    private String tokenType = "Bearer";
    private String username;
    private long expiresInMs;

    public AuthResponse(String token, String username, long expiresInMs) {
        this.token = token;
        this.tokenType = "Bearer";
        this.username = username;
        this.expiresInMs = expiresInMs;
    }
}
