package com.owasp.lab.service;

import com.owasp.lab.model.Comment;
import com.owasp.lab.repository.CommentRepository;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class CommentService {

    private final CommentRepository commentRepository;

    public CommentService(CommentRepository commentRepository) {
        this.commentRepository = commentRepository;
    }

    public Comment save(Comment comment) {
        return commentRepository.save(comment);
    }

    public List<Comment> findAll() {
        return commentRepository.findAll();
    }

    public Comment findById(Long id) {
        return commentRepository.findById(id).orElse(null);
    }
}
