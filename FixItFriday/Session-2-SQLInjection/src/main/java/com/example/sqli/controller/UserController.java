package com.example.sqli.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.example.sqli.repository.UserRepository;

@RestController
@RequestMapping("/api")
public class UserController {

    @Autowired
    private UserRepository userRepository;

    @GetMapping("/jpa/unsafe")
    public List<?> searchJpaUnsafe(@RequestParam String name) {
        return userRepository.findByJpqlUnsafe(name);
    }

    @GetMapping("/jdbc/unsafe")
    public List<?> searchJdbcUnsafe(@RequestParam String name) {
        return userRepository.findByJdbcUnsafe(name);
    }

    @GetMapping("/safe")
    public List<?> searchSafe(@RequestParam String name) {
        return userRepository.findByJpqlSafe(name);
    }
}