package com.example.idor.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import com.example.idor.entity.Invoice;

public interface InvoiceRepository extends JpaRepository<Invoice, Long> {
    List<Invoice> findByCustomerId(Long customerId);
    List<Invoice> findByOrderId(Long orderId);
}
