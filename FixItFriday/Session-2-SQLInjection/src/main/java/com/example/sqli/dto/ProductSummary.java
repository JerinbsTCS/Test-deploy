package com.example.sqli.dto;

import java.math.BigDecimal;

public record ProductSummary(Long id, String name, BigDecimal price) {
}