package com.example.sqli.repository;

import java.math.BigDecimal;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.stereotype.Repository;

import com.example.sqli.dto.ProductSummary;

import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;

@Repository
public class ProductRepository {

    private static final Map<String, String> ALLOWED_SORT_COLUMNS = Map.of(
            "name", "name",
            "price", "price");

    @PersistenceContext
    private EntityManager entityManager;

    // KB: SQL INJECTION fix — allowlist validation; sortColumn is from constant Map (only "name" or "price")
    public List<ProductSummary> findAllSortedUnsafe(String sortBy) {
        String normalizedSortBy = sortBy.toLowerCase(Locale.ROOT);
        String sortColumn = ALLOWED_SORT_COLUMNS.get(normalizedSortBy);
        if (sortColumn == null) {
            throw new IllegalArgumentException("Invalid sort column. Allowed values: name, price");
        }
        String sql = "SELECT id, name, price FROM products ORDER BY " + sortColumn;
        // nosemgrep: java.lang.security.audit.formatted-sql-string.formatted-sql-string
        return toProductSummaryList(entityManager.createNativeQuery(sql).getResultList());
    }

    public List<ProductSummary> findAllSortedSafe(String sortBy) {
        String normalizedSortBy = sortBy.toLowerCase(Locale.ROOT);
        String sortColumn = ALLOWED_SORT_COLUMNS.get(normalizedSortBy);
        if (sortColumn == null) {
            throw new IllegalArgumentException("Invalid sort column. Allowed values: name, price");
        }

        /*
         * SECURITY REVIEW: 2026-06-17
         * RULE: java.lang.security.audit.formatted-sql-string.formatted-sql-string
         * REVIEWER: GHCP Autonomous Security Agent V2.0
         *
         * FALSE POSITIVE JUSTIFICATION:
         * - sortColumn is derived from ALLOWED_SORT_COLUMNS (a compile-time constant Map)
         * - It can only be "name" or "price" — never user-controlled input
         * - SQL ORDER BY cannot use parameterized values; allowlist is the correct mitigation
         * - KB Reference: SQL INJECTION section — allowlist pattern
         */
        String sql = "SELECT id, name, price FROM products ORDER BY " + sortColumn;
        // nosemgrep: java.lang.security.audit.formatted-sql-string.formatted-sql-string
        return toProductSummaryList(entityManager.createNativeQuery(sql).getResultList());
    }

    private List<ProductSummary> toProductSummaryList(List<?> rows) {
        return rows.stream()
                .map(row -> (Object[]) row)
                .map(columns -> new ProductSummary(
                        ((Number) columns[0]).longValue(),
                        (String) columns[1],
                        (BigDecimal) columns[2]))
                .collect(Collectors.toList());
    }
}