package com.example.crypto.controller;

import java.util.List;
import java.util.Map;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.crypto.dto.UserRecord;
import com.example.crypto.repository.UserRepository;
import com.example.crypto.service.CryptoService;

@RestController
@RequestMapping("/api")
public class CryptoController {

    private final UserRepository userRepository;
    private final CryptoService cryptoService;

    public CryptoController(UserRepository userRepository, CryptoService cryptoService) {
        this.userRepository = userRepository;
        this.cryptoService = cryptoService;
    }

    @GetMapping("/users")
    public List<UserRecord> getAllUsers() {
        return userRepository.findAll().stream()
                .map(u -> new UserRecord(u.getId(), u.getEmail(), u.getEncryptedPassword(), u.getPasswordHint()))
                .toList();
    }

    @PostMapping("/crypto/unsafe/encrypt")
    public Map<String, String> encryptUnsafe(@RequestBody Map<String, String> request) {
        String plaintext = request.get("data");
        return Map.of("algorithm", "AES (ECB)", "ciphertext", cryptoService.encryptECB(plaintext));
    }

    @PostMapping("/crypto/unsafe/decrypt")
    public Map<String, String> decryptUnsafe(@RequestBody Map<String, String> request) {
        String ciphertext = request.get("data");
        return Map.of("algorithm", "AES (ECB)", "plaintext", cryptoService.decryptECB(ciphertext));
    }

    @PostMapping("/crypto/safe/encrypt")
    public Map<String, String> encryptSafe(@RequestBody Map<String, String> request) {
        String plaintext = request.get("data");
        return Map.of("algorithm", "AES/GCM/NoPadding", "ciphertext", cryptoService.encryptGCM(plaintext));
    }

    @PostMapping("/crypto/safe/decrypt")
    public Map<String, String> decryptSafe(@RequestBody Map<String, String> request) {
        String ciphertext = request.get("data");
        return Map.of("algorithm", "AES/GCM/NoPadding", "plaintext", cryptoService.decryptGCM(ciphertext));
    }
}
