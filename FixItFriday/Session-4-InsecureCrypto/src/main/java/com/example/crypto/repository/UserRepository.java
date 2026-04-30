package com.example.crypto.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import com.example.crypto.entity.User;

public interface UserRepository extends JpaRepository<User, Long> {
    List<User> findByEncryptedPassword(String encryptedPassword);
}
