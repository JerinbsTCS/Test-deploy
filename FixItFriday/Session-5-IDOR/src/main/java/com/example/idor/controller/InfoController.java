package com.example.idor.controller;

import java.security.Principal;
import java.util.List;
import java.util.Map;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.idor.entity.Customer;
import com.example.idor.repository.CustomerRepository;

@RestController
@RequestMapping("/api")
public class InfoController {

    private final CustomerRepository customerRepo;

    public InfoController(CustomerRepository customerRepo) {
        this.customerRepo = customerRepo;
    }

    @GetMapping("/public/info")
    public Map<String, Object> getLabInfo() {
        return Map.of(
            "lab", "Session 5 — IDOR (Insecure Direct Object Reference)",
            "scenario", "ShopEZ — an e-commerce platform with orders, invoices, and wishlists",
            "vulnerability", "API endpoints accept customer/order/invoice IDs without verifying the authenticated user owns that data",
            "credentials", Map.of(
                "john", "john123 (customer, id=1)",
                "sarah", "sarah123 (customer, id=2)",
                "mike", "mike123 (customer, id=3)",
                "emma", "emma123 (customer, id=4)",
                "support", "support123 (support staff)",
                "admin", "admin123 (admin, id=6)"
            ),
            "endpoints", Map.of(
                "vulnerable (v1)", List.of(
                    "GET /api/v1/customers/{id}/profile",
                    "GET /api/v1/customers/{id}/orders",
                    "GET /api/v1/customers/{id}/invoices",
                    "GET /api/v1/customers/{id}/wishlist",
                    "GET /api/v1/orders/{id}",
                    "GET /api/v1/orders/{id}/invoice",
                    "GET /api/v1/invoices/{id}",
                    "GET /api/v1/customers/{id}/full-account"
                ),
                "secure (v2)", List.of(
                    "GET /api/v2/customers/{id}/profile",
                    "GET /api/v2/customers/{id}/orders",
                    "GET /api/v2/customers/{id}/invoices",
                    "GET /api/v2/customers/{id}/wishlist",
                    "GET /api/v2/orders/{id}",
                    "GET /api/v2/orders/{id}/invoice",
                    "GET /api/v2/invoices/{id}",
                    "GET /api/v2/customers/{id}/full-account"
                )
            ),
            "ctf_hint", "The admin (id=6) placed a very special order..."
        );
    }

    @GetMapping("/whoami")
    public Map<String, Object> whoAmI(Principal principal) {
        String username = principal.getName();
        Customer customer = customerRepo.findByUsername(username).orElse(null);
        return Map.of(
            "username", username,
            "customerId", customer != null ? customer.getId() : "N/A (staff account)",
            "message", "Use your customer ID to access YOUR orders. Can you see others'?"
        );
    }
}
