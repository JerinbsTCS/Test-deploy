package com.example.idor.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import com.example.idor.entity.Order;

public interface OrderRepository extends JpaRepository<Order, Long> {
    List<Order> findByCustomerId(Long customerId);
}
