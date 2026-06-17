package com.example.sqli;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.transaction.Transactional;

@Component
public class DataSeeder implements ApplicationRunner {

    @PersistenceContext
    private EntityManager entityManager;

    @Value("${app.ctf-flag}")
    private String ctfFlag;

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        entityManager.createNativeQuery(
                "INSERT INTO users (username, role, description) VALUES (:username, :role, :description)")
                .setParameter("username", "ctf")
                .setParameter("role", "USER")
                .setParameter("description", ctfFlag)
                .executeUpdate();
    }
}
