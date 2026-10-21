package com.utch.backendauth.service;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory implementation of {@link UserDetailsService}.
 *
 * Two hard-coded users are registered at startup:
 *   - admin / admin123  (role: ADMIN, USER)
 *   - user  / user123   (role: USER)
 *
 * Passwords are stored BCrypt-hashed.  A {@link ConcurrentHashMap} acts as the
 * "database" so new users registered via /api/auth/register persist for the
 * lifetime of the application process.
 */
@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    private final PasswordEncoder passwordEncoder;

    /** username -> UserDetails map (in-memory "database"). */
    private final Map<String, UserDetails> users = new ConcurrentHashMap<>();

    public UserDetailsServiceImpl(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
        seedUsers();
    }

    // -----------------------------------------------------------------
    // UserDetailsService contract
    // -----------------------------------------------------------------

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserDetails user = users.get(username.toLowerCase());
        if (user == null) {
            throw new UsernameNotFoundException("User not found: " + username);
        }
        return user;
    }

    // -----------------------------------------------------------------
    // Registration helper (called by AuthController)
    // -----------------------------------------------------------------

    /**
     * Register a new user with the ROLE_USER authority.
     *
     * @param username plain username (stored lower-case)
     * @param rawPassword plain-text password (BCrypt-hashed before storage)
     * @throws IllegalArgumentException if the username is already taken
     */
    public UserDetails registerUser(String username, String rawPassword) {
        String key = username.toLowerCase();
        if (users.containsKey(key)) {
            throw new IllegalArgumentException("Username already exists: " + username);
        }

        UserDetails newUser = User.builder()
                .username(key)
                .password(passwordEncoder.encode(rawPassword))
                .roles("USER")
                .build();

        users.put(key, newUser);
        return newUser;
    }

    /**
     * Check whether a username is already taken.
     */
    public boolean userExists(String username) {
        return users.containsKey(username.toLowerCase());
    }

    // -----------------------------------------------------------------
    // Seed data
    // -----------------------------------------------------------------

    private void seedUsers() {
        // admin / admin123  — roles: USER + ADMIN
        UserDetails admin = User.builder()
                .username("admin")
                .password(passwordEncoder.encode("admin123"))
                .roles("USER", "ADMIN")
                .build();

        // user / user123  — role: USER
        UserDetails regularUser = User.builder()
                .username("user")
                .password(passwordEncoder.encode("user123"))
                .roles("USER")
                .build();

        users.put("admin", admin);
        users.put("user", regularUser);
    }
}
