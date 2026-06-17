package com.example.idor.controller;

import java.util.List;
import java.util.Map;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.idor.entity.Customer;
import com.example.idor.entity.Invoice;
import com.example.idor.entity.Order;
import com.example.idor.entity.WishlistItem;
import com.example.idor.repository.CustomerRepository;
import com.example.idor.repository.InvoiceRepository;
import com.example.idor.repository.OrderRepository;
import com.example.idor.repository.WishlistRepository;

/**
 * VULNERABLE CONTROLLER — demonstrates IDOR.
 *
 * These endpoints accept a customer ID or order/invoice ID directly from the
 * URL path but NEVER verify that the authenticated user is allowed to access
 * that resource. Any authenticated user can enumerate IDs.
 */
@RestController
@RequestMapping("/api/v1")
public class VulnerableController {

    private final CustomerRepository customerRepo;
    private final OrderRepository orderRepo;
    private final InvoiceRepository invoiceRepo;
    private final WishlistRepository wishlistRepo;

    public VulnerableController(CustomerRepository customerRepo,
                                OrderRepository orderRepo,
                                InvoiceRepository invoiceRepo,
                                WishlistRepository wishlistRepo) {
        this.customerRepo = customerRepo;
        this.orderRepo = orderRepo;
        this.invoiceRepo = invoiceRepo;
        this.wishlistRepo = wishlistRepo;
    }

    // ─── VULNERABLE: No ownership check ─────────────────────────────────

    @GetMapping("/customers/{id}/profile")
    public Customer getCustomerProfile(@PathVariable Long id) {
        return customerRepo.findById(id)
                .orElseThrow(() -> new RuntimeException("Customer not found"));
    }

    @GetMapping("/customers/{id}/orders")
    public List<Order> getCustomerOrders(@PathVariable Long id) {
        return orderRepo.findByCustomerId(id);
    }

    @GetMapping("/customers/{id}/invoices")
    public List<Invoice> getCustomerInvoices(@PathVariable Long id) {
        return invoiceRepo.findByCustomerId(id);
    }

    @GetMapping("/customers/{id}/wishlist")
    public List<WishlistItem> getCustomerWishlist(@PathVariable Long id) {
        return wishlistRepo.findByCustomerId(id);
    }

    @GetMapping("/orders/{id}")
    public Order getOrder(@PathVariable Long id) {
        return orderRepo.findById(id)
                .orElseThrow(() -> new RuntimeException("Order not found"));
    }

    @GetMapping("/orders/{id}/invoice")
    public List<Invoice> getOrderInvoice(@PathVariable Long id) {
        return invoiceRepo.findByOrderId(id);
    }

    @GetMapping("/invoices/{id}")
    public Invoice getInvoice(@PathVariable Long id) {
        return invoiceRepo.findById(id)
                .orElseThrow(() -> new RuntimeException("Invoice not found"));
    }

    @GetMapping("/customers/{id}/full-account")
    public Map<String, Object> getFullAccount(@PathVariable Long id) {
        Customer customer = customerRepo.findById(id)
                .orElseThrow(() -> new RuntimeException("Customer not found"));
        List<Order> orders = orderRepo.findByCustomerId(id);
        List<Invoice> invoices = invoiceRepo.findByCustomerId(id);
        List<WishlistItem> wishlist = wishlistRepo.findByCustomerId(id);

        return Map.of(
            "customer", customer,
            "orders", orders,
            "invoices", invoices,
            "wishlist", wishlist
        );
    }
}
