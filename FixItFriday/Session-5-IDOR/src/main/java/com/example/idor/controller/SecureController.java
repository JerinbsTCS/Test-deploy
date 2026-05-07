package com.example.idor.controller;

import java.util.List;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import com.example.idor.entity.Customer;
import com.example.idor.entity.Invoice;
import com.example.idor.entity.Order;
import com.example.idor.entity.WishlistItem;
import com.example.idor.repository.CustomerRepository;
import com.example.idor.repository.InvoiceRepository;
import com.example.idor.repository.OrderRepository;
import com.example.idor.repository.WishlistRepository;

/**
 * SECURE CONTROLLER — demonstrates the fix for IDOR.
 *
 * Every endpoint verifies that the authenticated user owns the requested
 * resource, OR has a privileged role (SUPPORT/ADMIN) that grants access.
 */
@RestController
@RequestMapping("/api/v2")
public class SecureController {

    private final CustomerRepository customerRepo;
    private final OrderRepository orderRepo;
    private final InvoiceRepository invoiceRepo;
    private final WishlistRepository wishlistRepo;

    public SecureController(CustomerRepository customerRepo,
                            OrderRepository orderRepo,
                            InvoiceRepository invoiceRepo,
                            WishlistRepository wishlistRepo) {
        this.customerRepo = customerRepo;
        this.orderRepo = orderRepo;
        this.invoiceRepo = invoiceRepo;
        this.wishlistRepo = wishlistRepo;
    }

    // ─── SECURE: Ownership verification on every request ─────────────────

    @GetMapping("/customers/{id}/profile")
    public Customer getCustomerProfile(@PathVariable Long id, Authentication auth) {
        Customer customer = findCustomer(id);
        verifyAccess(customer, auth);
        return customer;
    }

    @GetMapping("/customers/{id}/orders")
    public List<Order> getCustomerOrders(@PathVariable Long id, Authentication auth) {
        Customer customer = findCustomer(id);
        verifyAccess(customer, auth);
        return orderRepo.findByCustomerId(id);
    }

    @GetMapping("/customers/{id}/invoices")
    public List<Invoice> getCustomerInvoices(@PathVariable Long id, Authentication auth) {
        Customer customer = findCustomer(id);
        verifyAccess(customer, auth);
        return invoiceRepo.findByCustomerId(id);
    }

    @GetMapping("/customers/{id}/wishlist")
    public List<WishlistItem> getCustomerWishlist(@PathVariable Long id, Authentication auth) {
        Customer customer = findCustomer(id);
        verifyAccess(customer, auth);
        return wishlistRepo.findByCustomerId(id);
    }

    @GetMapping("/orders/{id}")
    public Order getOrder(@PathVariable Long id, Authentication auth) {
        Order order = orderRepo.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
        Customer customer = findCustomer(order.getCustomerId());
        verifyAccess(customer, auth);
        return order;
    }

    @GetMapping("/orders/{id}/invoice")
    public List<Invoice> getOrderInvoice(@PathVariable Long id, Authentication auth) {
        Order order = orderRepo.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
        Customer customer = findCustomer(order.getCustomerId());
        verifyAccess(customer, auth);
        return invoiceRepo.findByOrderId(id);
    }

    @GetMapping("/invoices/{id}")
    public Invoice getInvoice(@PathVariable Long id, Authentication auth) {
        Invoice invoice = invoiceRepo.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
        Customer customer = findCustomer(invoice.getCustomerId());
        verifyAccess(customer, auth);
        return invoice;
    }

    @GetMapping("/customers/{id}/full-account")
    public Map<String, Object> getFullAccount(@PathVariable Long id, Authentication auth) {
        Customer customer = findCustomer(id);
        verifyAccess(customer, auth);

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

    // ─── Helpers ─────────────────────────────────────────────────────────

    private Customer findCustomer(Long id) {
        return customerRepo.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
    }

    private void verifyAccess(Customer customer, Authentication auth) {
        String currentUser = auth.getName();
        boolean isOwner = customer.getUsername().equals(currentUser);
        boolean isPrivileged = auth.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_SUPPORT")
                            || a.getAuthority().equals("ROLE_ADMIN"));

        if (!isOwner && !isPrivileged) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN,
                    "Access denied: you can only view your own account data");
        }
    }
}
