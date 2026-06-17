package com.example.idor.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Data;

@Entity
@Table(name = "orders")
@Data
public class Order {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private Long customerId;
    private String orderDate;
    private String status; // PENDING, SHIPPED, DELIVERED, CANCELLED
    private Double totalAmount;

    @Column(length = 1000)
    private String items; // JSON-like description of items
    private String trackingNumber;
    private String shippingAddress;
}
