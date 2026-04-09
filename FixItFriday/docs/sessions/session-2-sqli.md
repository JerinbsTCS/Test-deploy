# SQL Injection

**Date:** March 27, 2026 
**Vulnerability:** SQL Injection (CWE-89)  
**OWASP Category:** [A05:2025 – Injection](../reference/owasp-top-10.md)

---

## What Was Demonstrated

In this session, we explored **SQL Injection** — a vulnerability where user-supplied input is interpolated directly into SQL queries, allowing attackers to manipulate database logic, extract data, or bypass authentication.

We built a Spring Boot app with an in-memory H2 database containing users and products. The app has both **vulnerable** and **secure** versions of each endpoint:

- **User search** — JPQL and JDBC injection via string concatenation
- **Product sorting** — ORDER BY injection via unsanitized column names

A hidden CTF flag is seeded into the database at startup via a `DataSeeder` component that reads from an environment variable, keeping secrets out of source code.

---

## Resources

### :material-docker: Container Images

```bash
# Pull and run the app
docker pull ghcr.io/<owner>/<repo>/fixitfriday/session-2-sqlinjection:latest
docker run -p 8080:8080 -e S2_FLAG="flag{your_flag_here}" ghcr.io/<owner>/<repo>/fixitfriday/session-2-sqlinjection:latest
```

### :material-github: Source Code

- **Session-2-SQLInjection** — Spring Boot app with vulnerable and secure SQL query patterns
- **Swagger UI** available at `/swagger-ui.html` when the app is running

---

## API Endpoints

| Endpoint | Method | Parameter | Type |
|----------|--------|-----------|------|
| `/api/jpa/unsafe` | GET | `name` | Vulnerable (JPQL concatenation) |
| `/api/jdbc/unsafe` | GET | `name` | Vulnerable (raw SQL concatenation) |
| `/api/safe` | GET | `name` | Secure (parameterized JPQL) |
| `/api/products/unsafe` | GET | `sortBy` | Vulnerable (ORDER BY injection) |
| `/api/products/safe` | GET | `sortBy` | Secure (allowlist validation) |

---

## Vulnerability Details

### 1. User Search — JPQL Injection (String Concatenation)

#### Vulnerable Code

The `findByJpqlUnsafe` method concatenates user input directly into a JPQL query string:

```java
public List<UserSummary> findByJpqlUnsafe(String name) {
    String jpql = "SELECT new com.example.sqli.dto.UserSummary(u.id, u.username, u.role) "
            + "FROM User u WHERE u.username = '" + name + "'";
    return entityManager.createQuery(jpql, UserSummary.class).getResultList();
}
```

#### Exploitation

```bash
# Normal usage
curl "http://localhost:8080/api/jpa/unsafe?name=admin"

# Extract all users (tautology injection)
curl "http://localhost:8080/api/jpa/unsafe?name=' OR '1'='1"

# Extract the hidden CTF flag from the description field
curl "http://localhost:8080/api/jpa/unsafe?name=' UNION SELECT u.id, u.description, u.role FROM User u WHERE u.username='ctf' --"
```

#### Secure Code

Uses named parameters — the input is bound as a value, not part of the query structure:

```java
public List<UserSummary> findByJpqlSafe(String name) {
    return entityManager.createQuery(
            "SELECT new com.example.sqli.dto.UserSummary(u.id, u.username, u.role) "
            + "FROM User u WHERE u.username = :name",
            UserSummary.class)
            .setParameter("name", name)
            .getResultList();
}
```

---

### 2. User Search — JDBC Injection (Raw SQL Concatenation)

#### Vulnerable Code

```java
public List<UserSummary> findByJdbcUnsafe(String name) {
    String sql = "SELECT id, username, role FROM users WHERE username = '" + name + "'";
    return toUserSummaryList(entityManager.createNativeQuery(sql).getResultList());
}
```

#### Exploitation

```bash
# Extract all users
curl "http://localhost:8080/api/jdbc/unsafe?name=' OR '1'='1"

# UNION-based extraction of descriptions (flags)
curl "http://localhost:8080/api/jdbc/unsafe?name=' UNION SELECT id, description, role FROM users --"
```

#### Secure Code

Uses positional parameters with `setParameter`:

```java
public List<UserSummary> findByJdbcSafe(String name) {
    Query query = entityManager.createNativeQuery(
            "SELECT id, username, role FROM users WHERE username = ?");
    query.setParameter(1, name);
    return toUserSummaryList(query.getResultList());
}
```

---

### 3. Product Sorting — ORDER BY Injection

#### Vulnerable Code

The `sortBy` parameter is concatenated directly into the `ORDER BY` clause:

```java
public List<ProductSummary> findAllSortedUnsafe(String sortBy) {
    String sql = "SELECT id, name, price FROM products ORDER BY " + sortBy;
    return toProductSummaryList(entityManager.createNativeQuery(sql).getResultList());
}
```

!!! warning "Why parameterized queries don't work here"
    Column names and SQL keywords (`ORDER BY`, table names) **cannot** be parameterized — they're part of the query structure, not values. You must use an allowlist.

#### Exploitation

```bash
# Normal usage
curl "http://localhost:8080/api/products/unsafe?sortBy=price"

# Boolean-based blind injection — extract data via conditional sorting
curl "http://localhost:8080/api/products/unsafe?sortBy=CASE WHEN (SELECT COUNT(*) FROM users)>0 THEN name ELSE price END"

# Error-based injection
curl "http://localhost:8080/api/products/unsafe?sortBy=1;DROP TABLE products--"
```

#### Secure Code

Uses an allowlist to map user input to valid column names:

```java
private static final Map<String, String> ALLOWED_SORT_COLUMNS = Map.of(
        "name", "name",
        "price", "price");

public List<ProductSummary> findAllSortedSafe(String sortBy) {
    String normalizedSortBy = sortBy.toLowerCase(Locale.ROOT);
    String sortColumn = ALLOWED_SORT_COLUMNS.get(normalizedSortBy);
    if (sortColumn == null) {
        throw new IllegalArgumentException("Invalid sort column. Allowed values: name, price");
    }
    String sql = "SELECT id, name, price FROM products ORDER BY " + sortColumn;
    return toProductSummaryList(entityManager.createNativeQuery(sql).getResultList());
}
```

---

## CTF Flag

The flag is **not** hardcoded in source code. It's injected at runtime:

1. The `S2_FLAG` environment variable is set in the Docker container (via build arg)
2. Spring Boot reads it via `application.properties`: `app.ctf-flag=${S2_FLAG:flag{default}}`
3. A `DataSeeder` component inserts the CTF user at startup with the flag in the `description` field
4. The flag is only visible through the `description` column — the safe endpoints only return `id`, `username`, and `role`

**Goal:** Use SQL injection to extract the `description` field of the `ctf` user.

---

## Seed Data

```sql
INSERT INTO users (username, role, description) VALUES ('admin', 'SUPERUSER', 'Administrator with full access');
INSERT INTO users (username, role, description) VALUES ('alice', 'USER', 'Regular user Alice');
INSERT INTO users (username, role, description) VALUES ('bob', 'USER', 'Regular user Bob');
-- CTF user with flag injected at runtime via DataSeeder

INSERT INTO products (name, price) VALUES ('Laptop', 1299.99);
INSERT INTO products (name, price) VALUES ('Keyboard', 89.50);
INSERT INTO products (name, price) VALUES ('Mouse', 39.99);
INSERT INTO products (name, price) VALUES ('Monitor', 349.00);
```

---

## Dockerfile

```dockerfile
FROM eclipse-temurin:17-jre
WORKDIR /app

ARG S2_FLAG
ENV S2_FLAG=${S2_FLAG}

COPY ./target/*.jar app.jar

EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
```

!!! info "Flag injection"
    The `S2_FLAG` build arg is passed from GitHub Actions environment variables and set as a runtime environment variable. Spring Boot reads it via `${S2_FLAG}` in `application.properties`.

---

## Key Takeaways

- **Never** concatenate user input into SQL queries — use parameterized queries / prepared statements
- JPQL is **not** immune to injection — string concatenation in JPQL is just as dangerous as in raw SQL
- `ORDER BY` and other structural SQL elements **cannot** be parameterized — use allowlists
- Keep secrets (flags, credentials) out of source code — inject them via environment variables at runtime
- The safe endpoints intentionally restrict which columns are returned (no `description`), demonstrating API-level data exposure controls
- Use Swagger UI (`/swagger-ui.html`) to explore and test endpoints during development

---
