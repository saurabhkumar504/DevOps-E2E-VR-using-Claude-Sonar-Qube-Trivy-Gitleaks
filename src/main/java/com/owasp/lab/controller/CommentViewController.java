package com.owasp.lab.controller;

import com.owasp.lab.model.Comment;
import com.owasp.lab.service.CommentService;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Renders comments as raw HTML so the stored XSS payload fires in the
 * browser. DO NOT use this pattern in real applications.
 */
@RestController
@RequestMapping("/comments")
public class CommentViewController {

    private final CommentService commentService;

    public CommentViewController(CommentService commentService) {
        this.commentService = commentService;
    }

    // VULNERABILITY (OWASP A03:2021 - Injection / XSS - Stored):
    // All comments are concatenated into the HTML response without
    // escaping. A malicious comment body will execute in the browser.
    @GetMapping(produces = MediaType.TEXT_HTML_VALUE)
    public String viewAll() {
        StringBuilder sb = new StringBuilder();
        sb.append("<html><body><h1>Comments</h1>");
        List<Comment> comments = commentService.findAll();
        for (Comment c : comments) {
            // VULNERABILITY: raw concatenation, no escaping.
            sb.append("<div class='comment'>")
              .append("<b>").append(c.getAuthor()).append(":</b> ")
              .append(c.getBody())
              .append("</div>");
        }
        sb.append("</body></html>");
        return sb.toString();
    }

    @GetMapping(value = "/{id}", produces = MediaType.TEXT_HTML_VALUE)
    public String viewOne(@PathVariable Long id) {
        Comment c = commentService.findById(id);
        if (c == null) {
            return "<html><body>Not found</body></html>";
        }
        // VULNERABILITY: raw concatenation, no escaping.
        return "<html><body><h1>Comment</h1><div><b>"
                + c.getAuthor() + ":</b> " + c.getBody() + "</div></body></html>";
    }
}
