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
        String sql = "SELECT * FROM users WHERE username = ?";
        System.out.println("[VULNERABILITY] Executing raw SQL: " + sql);

        try {
            List<User> rows = entityManager
                    .createNativeQuery(sql, User.class).setParameter(1, username)
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
        // VULNERABILITY FIX (AI auto-remediation, marker FIX_PLAIN_PASSWORD_APPLIED):
        //   - Look the user up by username only (no password in the SQL).
        //   - Compare the supplied password to the stored password in Java.
        //   - TODO: replace the String.equals check with BCryptPasswordEncoder.matches().
        String sql = "SELECT * FROM users WHERE username = ?";
        System.out.println("[VULNERABILITY-FIXED] Login SQL: " + sql);

        try {
            @SuppressWarnings("unchecked")
            java.util.List<User> rows = entityManager
                    .createNativeQuery(sql, User.class)
                    .setParameter(1, username)
                    .getResultList();
            if (rows.isEmpty()) {
                return null;
            }
            User u = rows.get(0);
            if (u.getPassword() == null || !u.getPassword().equals(password)) {
                return null;
            }
            return u;
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
