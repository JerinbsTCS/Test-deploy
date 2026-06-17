package com.example.crypto.dto;

public record UserRecord(Long id, String email, String encryptedPassword, String passwordHint) {
}
