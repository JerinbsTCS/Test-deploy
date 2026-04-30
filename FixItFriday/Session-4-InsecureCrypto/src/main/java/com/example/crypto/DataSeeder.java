package com.example.crypto;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

import com.example.crypto.entity.User;
import com.example.crypto.repository.UserRepository;
import com.example.crypto.service.CryptoService;

@Component
public class DataSeeder implements ApplicationRunner {

    private final UserRepository userRepository;
    private final CryptoService cryptoService;
    private final String ctfFlag;

    public DataSeeder(UserRepository userRepository, CryptoService cryptoService,
                      @Value("${app.ctf-flag}") String ctfFlag) {
        this.userRepository = userRepository;
        this.cryptoService = cryptoService;
        this.ctfFlag = ctfFlag;
    }

    @Override
    public void run(ApplicationArguments args) {
        seed("bob.martin@example.com",    "sunshine2024",   "weather + year");
        seed("john.smith@example.com",    "123456",         "ascending numbers");
        seed("admin@example.com",         "Tr0ub4dor&3",    "correct horse battery staple");
        seed("sarah.jones@example.com",   "123456",         "six");
        seed("carol.white@example.com",   "monkey",         "primate");
        seed("frank.hill@example.com",    "abc123",         "first letters + first numbers");
        seed("lisa.wang@example.com",     "123456",         "keyboard top row numbers");
    }

    private void seed(String email, String password, String hint) {
        User user = new User();
        user.setEmail(email);
        user.setEncryptedPassword(cryptoService.encryptGCM(password));
        user.setPasswordHint(hint);
        userRepository.save(user);
    }
}
