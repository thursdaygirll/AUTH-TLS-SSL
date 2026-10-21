package com.utch.backendauth.controller;

import com.utch.backendauth.config.JwtConfig;
import com.utch.backendauth.dto.AuthRequest;
import com.utch.backendauth.dto.AuthResponse;
import com.utch.backendauth.service.UserDetailsServiceImpl;
import com.utch.backendauth.security.JwtUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Handles authentication endpoints.
 *
 * POST /api/auth/login    — authenticate and receive a JWT
 * POST /api/auth/register — register a new user and receive a JWT
 *
 * Both endpoints are publicly accessible (configured in SecurityConfig).
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);

    private final AuthenticationManager authenticationManager;
    private final UserDetailsServiceImpl userDetailsService;
    private final JwtUtil jwtUtil;
    private final JwtConfig jwtConfig;

    public AuthController(AuthenticationManager authenticationManager,
                          UserDetailsServiceImpl userDetailsService,
                          JwtUtil jwtUtil,
                          JwtConfig jwtConfig) {
        this.authenticationManager = authenticationManager;
        this.userDetailsService = userDetailsService;
        this.jwtUtil = jwtUtil;
        this.jwtConfig = jwtConfig;
    }

    // -----------------------------------------------------------------
    // POST /api/auth/login
    // -----------------------------------------------------------------

    /**
     * Authenticate an existing user and return a JWT bearer token.
     *
     * Request body:
     * <pre>{ "username": "admin", "password": "admin123" }</pre>
     *
     * Successful response (200):
     * <pre>{ "token": "...", "tokenType": "Bearer", "username": "admin", "expiresInMs": 3600000 }</pre>
     *
     * Failed response (401):
     * <pre>{ "timestamp": "...", "status": 401, "error": "Unauthorized", "message": "..." }</pre>
     */
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody AuthRequest request) {
        if (request.getUsername() == null || request.getUsername().isBlank()
                || request.getPassword() == null || request.getPassword().isBlank()) {
            return buildErrorResponse(HttpStatus.BAD_REQUEST,
                    "Username and password must not be blank.", "/api/auth/login");
        }

        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getUsername().toLowerCase(),
                            request.getPassword()));

            UserDetails userDetails = (UserDetails) authentication.getPrincipal();
            String token = jwtUtil.generateToken(userDetails);

            log.info("User '{}' logged in successfully.", userDetails.getUsername());

            return ResponseEntity.ok(new AuthResponse(
                    token,
                    userDetails.getUsername(),
                    jwtConfig.getExpirationMs()));

        } catch (BadCredentialsException e) {
            log.warn("Login failed for user '{}': bad credentials", request.getUsername());
            return buildErrorResponse(HttpStatus.UNAUTHORIZED,
                    "Invalid username or password.", "/api/auth/login");
        }
    }

    // -----------------------------------------------------------------
    // POST /api/auth/register
    // -----------------------------------------------------------------

    /**
     * Register a new user and immediately return a JWT bearer token.
     *
     * Request body:
     * <pre>{ "username": "newuser", "password": "mypassword" }</pre>
     *
     * Successful response (201):
     * <pre>{ "token": "...", "tokenType": "Bearer", "username": "newuser", "expiresInMs": 3600000 }</pre>
     */
    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody AuthRequest request) {
        if (request.getUsername() == null || request.getUsername().isBlank()
                || request.getPassword() == null || request.getPassword().isBlank()) {
            return buildErrorResponse(HttpStatus.BAD_REQUEST,
                    "Username and password must not be blank.", "/api/auth/register");
        }

        if (request.getPassword().length() < 6) {
            return buildErrorResponse(HttpStatus.BAD_REQUEST,
                    "Password must be at least 6 characters.", "/api/auth/register");
        }

        if (userDetailsService.userExists(request.getUsername())) {
            return buildErrorResponse(HttpStatus.CONFLICT,
                    "Username '" + request.getUsername() + "' is already taken.",
                    "/api/auth/register");
        }

        UserDetails newUser = userDetailsService.registerUser(
                request.getUsername(), request.getPassword());

        String token = jwtUtil.generateToken(newUser);

        log.info("New user '{}' registered successfully.", newUser.getUsername());

        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(new AuthResponse(token, newUser.getUsername(), jwtConfig.getExpirationMs()));
    }

    // -----------------------------------------------------------------
    // Error helper
    // -----------------------------------------------------------------

    private ResponseEntity<Map<String, Object>> buildErrorResponse(HttpStatus status,
                                                                    String message,
                                                                    String path) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("timestamp", Instant.now().toString());
        body.put("status", status.value());
        body.put("error", status.getReasonPhrase());
        body.put("message", message);
        body.put("path", path);
        return ResponseEntity.status(status).body(body);
    }
}
