package com.example.idor.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Data;

@Entity
@Table(name = "invoices")
@Data
public class Invoice {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private Long customerId;
    private Long orderId;
    private String invoiceDate;
    private Double subtotal;
    private Double tax;
    private Double total;
    private String paymentMethod; // VISA ending 4242, PayPal, etc.
    private String billingAddress;
    private String status; // PAID, PENDING, REFUNDED
    private String cardLast4;
}
