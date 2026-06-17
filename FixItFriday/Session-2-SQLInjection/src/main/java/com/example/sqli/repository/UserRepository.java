package com.example.sqli.repository;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.stereotype.Repository;

import com.example.sqli.dto.UserSummary;

import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.persistence.Query;

@Repository
public class UserRepository {

    @PersistenceContext
    private EntityManager entityManager;

    // 1. JPA (Named Parameter) — KB: SQL INJECTION / formatted-sql-string fix
    public List<UserSummary> findByJpqlUnsafe(String name) {
        return entityManager.createQuery(
                "SELECT new com.example.sqli.dto.UserSummary(u.id, u.username, u.role) FROM User u WHERE u.username = :name",
                UserSummary.class)
                .setParameter("name", name)
                .getResultList();
    }

    // 2. JPA SAFE (Named Parameters)
    public List<UserSummary> findByJpqlSafe(String name) {
        return entityManager.createQuery(
                "SELECT new com.example.sqli.dto.UserSummary(u.id, u.username, u.role) FROM User u WHERE u.username = :name",
                UserSummary.class)
                .setParameter("name", name)
                .getResultList();
    }

    // 3. JDBC (Positional Parameter) — KB: SQL INJECTION / formatted-sql-string fix
    public List<UserSummary> findByJdbcUnsafe(String name) {
        Query query = entityManager.createNativeQuery("SELECT id, username, role FROM users WHERE username = ?");
        query.setParameter(1, name);
        return toUserSummaryList(query.getResultList());
    }

    // 4. JDBC SAFE (Prepared Statement / Positional Parameter)
    public List<UserSummary> findByJdbcSafe(String name) {
        Query query = entityManager.createNativeQuery("SELECT id, username, role FROM users WHERE username = ?");
        query.setParameter(1, name);
        return toUserSummaryList(query.getResultList());
    }

    private List<UserSummary> toUserSummaryList(List<?> rows) {
        return rows.stream()
                .map(row -> (Object[]) row)
                .map(columns -> new UserSummary(((Number) columns[0]).longValue(), (String) columns[1], (String) columns[2]))
                .collect(Collectors.toList());
    }
}