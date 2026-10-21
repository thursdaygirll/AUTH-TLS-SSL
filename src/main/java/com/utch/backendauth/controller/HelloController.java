package com.utch.backendauth.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Protected endpoint examples.
 *
 * GET /api/hello — requires any authenticated user (valid JWT)
 */
@RestController
@RequestMapping("/api")
public class HelloController {

    /**
     * Returns a greeting and basic info about the authenticated caller.
     * Access requires a valid Bearer token in the Authorization header.
     *
     * Example response:
     * <pre>
     * {
     *   "message": "Hello, admin! You are authenticated.",
     *   "username": "admin",
     *   "roles": ["ROLE_USER", "ROLE_ADMIN"],
     *   "timestamp": "2025-01-01T12:00:00Z"
     * }
     * </pre>
     */
    @GetMapping("/hello")
    public ResponseEntity<Map<String, Object>> hello(Authentication authentication) {
        String username = authentication.getName();

        List<String> roles = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("message", "Hello, " + username + "! You are authenticated.");
        response.put("username", username);
        response.put("roles", roles);
        response.put("timestamp", Instant.now().toString());

        return ResponseEntity.ok(response);
    }

    /**
     * A publicly accessible endpoint — no token required.
     * Demonstrates the /api/public/** permit-all rule.
     */
    @GetMapping("/public/info")
    public ResponseEntity<Map<String, Object>> publicInfo() {
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("message", "This is a public endpoint. No authentication required.");
        response.put("timestamp", Instant.now().toString());
        return ResponseEntity.ok(response);
    }
}
