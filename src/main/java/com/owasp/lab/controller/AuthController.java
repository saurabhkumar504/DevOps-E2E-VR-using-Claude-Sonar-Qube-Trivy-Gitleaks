package com.owasp.lab.controller;

import com.owasp.lab.model.User;
import com.owasp.lab.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * Authentication endpoints.
 */
@RestController
@RequestMapping("/api")
public class AuthController {

    private final UserService userService;

    public AuthController(UserService userService) {
        this.userService = userService;
    }

    // ----------------------------------------------------------------
    // VULNERABILITY (OWASP A03:2021 - SQL Injection /
    //                OWASP A07:2021 - Broken Authentication):
    //
    // POST /api/login with JSON: {"username":"alice","password":"alice123"}
    //
    // Try a SQL injection bypass:
    //   username = ' OR '1'='1
    //   password = anything
    //
    // The plaintext password is also never hashed (A02:2021).
    // ----------------------------------------------------------------
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> body) {
        String username = body.getOrDefault("username", "");
        String password = body.getOrDefault("password", "");

        User u = userService.loginUnsafe(username, password);
        if (u == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Invalid credentials"));
        }
        return ResponseEntity.ok(Map.of(
                "id", u.getId(),
                "username", u.getUsername(),
                "role", u.getRole(),
                // VULNERABILITY: leaking password back to caller
                "password", u.getPassword()
        ));
    }

    // ----------------------------------------------------------------
    // VULNERABILITY (OWASP A01:2021 - Broken Access Control /
    //                OWASP A05:2021 - Security Misconfiguration):
    //
    // Creates a new user without authentication and stores the password
    // in plain text.
    // ----------------------------------------------------------------
    @PostMapping("/register")
    public ResponseEntity<User> register(@RequestBody Map<String, String> body) {
        String username = body.getOrDefault("username", "");
        String password = body.getOrDefault("password", "");
        String email    = body.getOrDefault("email", "");
        String role     = body.getOrDefault("role", "USER");

        User u = new User(username, password, email, role, 0.0);
        return ResponseEntity.ok(userService.save(u));
    }

    // ----------------------------------------------------------------
    // VULNERABILITY (OWASP A01:2021 - Broken Access Control):
    // Money transfer without authentication or CSRF protection.
    // (CSRF disabled globally in SecurityConfig.)
    // ----------------------------------------------------------------
    @PostMapping("/transfer")
    public ResponseEntity<?> transfer(@RequestBody Map<String, Object> body) {
        Long fromId = ((Number) body.get("fromId")).longValue();
        Long toId   = ((Number) body.get("toId")).longValue();
        Double amount = ((Number) body.get("amount")).doubleValue();

        User from = userService.findByIdUnsafe(fromId);
        User to   = userService.findByIdUnsafe(toId);

        if (from == null || to == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "User not found"));
        }
        // VULNERABILITY: no balance check, no ownership check, no auth
        from.setBalance(from.getBalance() - amount);
        to.setBalance(to.getBalance() + amount);
        userService.save(from);
        userService.save(to);

        return ResponseEntity.ok(Map.of(
                "status", "ok",
                "fromBalance", from.getBalance(),
                "toBalance", to.getBalance()
        ));
    }
}
