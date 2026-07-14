package com.owasp.lab.repository;

import com.owasp.lab.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

/**
 * Safe JPA repository (uses parameterised queries by default).
 * NOTE: the SQL Injection demo lives in the unsafe query in
 * {@link com.owasp.lab.service.UserService#findByUsernameUnsafe(String)}.
 */
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);
}
