package com.example.sqli.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.example.sqli.dto.ProductSummary;
import com.example.sqli.repository.ProductRepository;

@RestController
@RequestMapping("/api/products")
public class ProductController {

    @Autowired
    private ProductRepository productRepository;

    @GetMapping("/unsafe")
    public List<ProductSummary> sortProductsUnsafe(@RequestParam(defaultValue = "price") String sortBy) {
        return productRepository.findAllSortedUnsafe(sortBy);
    }

    @GetMapping("/safe")
    public List<ProductSummary> sortProductsSafe(@RequestParam(defaultValue = "price") String sortBy) {
        return productRepository.findAllSortedSafe(sortBy);
    }
}