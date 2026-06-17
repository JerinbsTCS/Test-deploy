package com.example.idor.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import com.example.idor.entity.WishlistItem;

public interface WishlistRepository extends JpaRepository<WishlistItem, Long> {
    List<WishlistItem> findByCustomerId(Long customerId);
}
