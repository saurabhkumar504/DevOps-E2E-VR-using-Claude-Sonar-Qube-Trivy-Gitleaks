package com.owasp.lab.controller;

import com.owasp.lab.model.Comment;
import com.owasp.lab.service.CommentService;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * Comment endpoints - used to demonstrate XSS.
 */
@RestController
@RequestMapping("/api/comment")
public class CommentController {

    private final CommentService commentService;

    public CommentController(CommentService commentService) {
        this.commentService = commentService;
    }

    // ----------------------------------------------------------------
    // VULNERABILITY (OWASP A03:2021 - Injection / XSS - Stored):
    // Comment body is stored raw and later echoed back inside HTML
    // WITHOUT escaping. POST a comment containing:
    //   <script>alert('XSS')</script>
    // and the script will fire when the HTML page is rendered.
    // ----------------------------------------------------------------
    @PostMapping
    public Comment create(@RequestBody Comment c) {
        return commentService.save(c);
    }

    @GetMapping
    public List<Comment> all() {
        return commentService.findAll();
    }

    // ----------------------------------------------------------------
    // VULNERABILITY (OWASP A03:2021 - Injection / XSS - Reflected):
    // The "name" query parameter is interpolated into HTML WITHOUT
    // escaping or sanitisation.
    //
    // Try: /api/comment/greet?name=<script>alert('XSS')</script>
    // ----------------------------------------------------------------
    @GetMapping(value = "/greet", produces = MediaType.TEXT_HTML_VALUE)
    public String greet(@RequestParam(value = "name", defaultValue = "World") String name) {
        // VULNERABILITY: directly concatenated into HTML response.
        return "<html><body><h1>Hello, " + name + "!</h1></body></html>";
    }
}
