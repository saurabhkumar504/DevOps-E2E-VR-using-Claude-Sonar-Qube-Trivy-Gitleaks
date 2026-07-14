package com.owasp.lab.service;

import com.owasp.lab.model.Product;
import com.owasp.lab.repository.ProductRepository;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class ProductService {

    private final ProductRepository productRepository;

    public ProductService(ProductRepository productRepository) {
        this.productRepository = productRepository;
    }

    public List<Product> findAll() {
        return productRepository.findAll();
    }

    public Product save(Product p) {
        return productRepository.save(p);
    }
}
