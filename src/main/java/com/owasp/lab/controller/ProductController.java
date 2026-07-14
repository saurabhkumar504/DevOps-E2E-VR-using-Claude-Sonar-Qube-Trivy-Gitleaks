package com.owasp.lab.controller;

import com.owasp.lab.model.Product;
import com.owasp.lab.service.ProductService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * Simple product endpoints used as additional demo targets.
 */
@RestController
@RequestMapping("/api/products")
public class ProductController {

    private final ProductService productService;

    public ProductController(ProductService productService) {
        this.productService = productService;
    }

    @GetMapping
    public List<Product> list() {
        return productService.findAll();
    }

    // VULNERABILITY (OWASP A01:2021 - Broken Access Control):
    // Anyone may create products without authentication.
    @PostMapping
    public ResponseEntity<Product> create(@RequestBody Product p) {
        return ResponseEntity.ok(productService.save(p));
    }
}
