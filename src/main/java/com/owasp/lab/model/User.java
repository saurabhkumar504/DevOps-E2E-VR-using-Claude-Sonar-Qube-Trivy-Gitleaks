package com.owasp.lab.model;

import jakarta.persistence.*;

/**
 * User entity.
 *
 * VULNERABILITY (OWASP A02:2021 - Cryptographic Failures /
 *                OWASP A07:2021 - Identification and Authentication Failures):
 * Passwords are stored as PLAIN TEXT. In a real system you MUST hash with
 * bcrypt / argon2 / scrypt and use a per-user salt.
 */
@Entity
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String username;

    // VULNERABILITY: storing plaintext password (A02 / A07)
    @Column(nullable = false)
    private String password;

    private String email;
    private String role;        // e.g. "USER", "ADMIN"
    private Double balance;     // for /transfer demo

    public User() {}

    public User(String username, String password, String email, String role, Double balance) {
        this.username = username;
        this.password = password;
        this.email = email;
        this.role = role;
        this.balance = balance;
    }

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }

    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }

    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }

    public String getRole() { return role; }
    public void setRole(String role) { this.role = role; }

    public Double getBalance() { return balance; }
    public void setBalance(Double balance) { this.balance = balance; }
}
