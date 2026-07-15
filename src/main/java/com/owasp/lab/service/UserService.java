package com.owasp.lab.service;

import com.owasp.lab.model.User;
import com.owasp.lab.repository.UserRepository;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;

/**
 * User service - intentionally insecure for the OWASP learning lab.
 */
@Service
public class UserService {

    private final UserRepository userRepository;

    @PersistenceContext
    private EntityManager entityManager;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    // -----------------------------------------------------------------
    // VULNERABILITY (OWASP A03:2021 - Injection: SQL Injection)
    //
    // The search term is concatenated into a raw SQL query.
    // An attacker can supply:   ' OR '1'='1
    // and dump every user row. NEVER do this in production code.
    // -----------------------------------------------------------------
    @SuppressWarnings("unchecked")
    @Transactional
    public List<User> findByUsernameUnsafe(String username) {
        // VULNERABILITY: SQL Injection example - user input concatenated directly.
        String sql = "SELECT * FROM users WHERE username = '" + username + "'";
        System.out.println("[VULNERABILITY] Executing raw SQL: " + sql);

        try {
            List<User> rows = entityManager
                    .createNativeQuery(sql, User.class)
                    .getResultList();
            return rows;
        } catch (Exception ex) {
            return new ArrayList<>();
        }
    }

    // -----------------------------------------------------------------
    // VULNERABILITY (OWASP A07:2021 - Broken Authentication):
    // The login endpoint compares plaintext passwords using String.equals.
    // No hashing, no salting, no constant-time compare.
    // -----------------------------------------------------------------
    public User loginUnsafe(String username, String password) {
        // VULNERABILITY: raw SQL with concatenated credentials.
        String sql = "SELECT * FROM users WHERE username = '"
                + username + "' AND password = '" + password + "'";
        System.out.println("[VULNERABILITY] Login SQL: " + sql);

        try {
            List<User> rows = entityManager
                    .createNativeQuery(sql, User.class)
                    .getResultList();
            return rows.isEmpty() ? null : rows.get(0);
        } catch (Exception ex) {
            return null;
        }
    }

    public User save(User user) {
        return userRepository.save(user);
    }

    // VULNERABILITY (OWASP A01:2021 - Broken Access Control / IDOR):
    // Returns any user by ID without verifying the requester is allowed
    // to see them.
    public User findByIdUnsafe(Long id) {
        return userRepository.findById(id).orElse(null);
    }

    public List<User> findAll() {
        return userRepository.findAll();
    }
}
