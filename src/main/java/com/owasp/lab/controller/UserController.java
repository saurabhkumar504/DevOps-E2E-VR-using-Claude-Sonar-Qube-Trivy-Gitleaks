package com.owasp.lab.controller;

import com.owasp.lab.model.User;
import com.owasp.lab.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * User-related REST endpoints.
 * Every endpoint below is intentionally vulnerable.
 */
@RestController
@RequestMapping("/api")
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    // ----------------------------------------------------------------
    // VULNERABILITY (OWASP A01:2021 - Broken Access Control / IDOR):
    // Anyone can list every user record - no authentication, no
    // authorisation.
    // ----------------------------------------------------------------
    @GetMapping("/users")
    public List<User> listUsers() {
        return userService.findAll();
    }

    // ----------------------------------------------------------------
    // VULNERABILITY (OWASP A01:2021 - IDOR):
    // The requester can fetch ANY user by ID. No check that the
    // requester is the resource owner or an admin.
    // ----------------------------------------------------------------
    @GetMapping("/profile/{id}")
    public ResponseEntity<User> getProfile(@PathVariable Long id) {
        User u = userService.findByIdUnsafe(id);
        if (u == null) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(u);
    }

    // ----------------------------------------------------------------
    // VULNERABILITY (OWASP A03:2021 - SQL Injection):
    // Concatenates the search term straight into the SQL query.
    // Try: /api/search?q=' OR '1'='1
    // ----------------------------------------------------------------
    @GetMapping("/search")
    public List<User> search(@RequestParam("q") String q) {
        return userService.findByUsernameUnsafe(q);
    }
}
