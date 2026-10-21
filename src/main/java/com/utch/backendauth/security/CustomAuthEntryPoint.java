package com.utch.backendauth.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Handles unauthenticated requests by returning HTTP 401 with a JSON body.
 *
 * This is triggered when:
 *   - No Authorization header is present.
 *   - The Bearer token is missing, malformed, expired, or has an invalid signature.
 *   - A TLS handshake error bubbles up as an AuthenticationException.
 */
@Component
public class CustomAuthEntryPoint implements AuthenticationEntryPoint {

    private static final Logger log = LoggerFactory.getLogger(CustomAuthEntryPoint.class);

    private final ObjectMapper objectMapper;

    public CustomAuthEntryPoint(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    public void commence(HttpServletRequest request,
                         HttpServletResponse response,
                         AuthenticationException authException) throws IOException {

        log.warn("Unauthorized request to '{}': {}", request.getRequestURI(), authException.getMessage());

        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("timestamp", Instant.now().toString());
        body.put("status", 401);
        body.put("error", "Unauthorized");
        body.put("message", buildMessage(request, authException));
        body.put("path", request.getRequestURI());

        objectMapper.writeValue(response.getOutputStream(), body);
    }

    /**
     * Generates a human-readable error message, distinguishing TLS-related
     * failures from ordinary missing/bad token errors.
     */
    private String buildMessage(HttpServletRequest request, AuthenticationException ex) {
        String cause = ex.getMessage() != null ? ex.getMessage().toLowerCase() : "";

        if (cause.contains("ssl") || cause.contains("tls") || cause.contains("handshake")) {
            return "TLS handshake failed. Ensure the client trusts the server certificate "
                 + "and is using TLSv1.2 or TLSv1.3.";
        }

        if (cause.contains("expired")) {
            return "JWT token has expired. Please log in again to obtain a new token.";
        }

        if (cause.contains("signature") || cause.contains("invalid")) {
            return "JWT token signature is invalid. Authentication rejected.";
        }

        return "Authentication is required to access this resource. "
             + "Provide a valid Bearer token in the Authorization header.";
    }
}
