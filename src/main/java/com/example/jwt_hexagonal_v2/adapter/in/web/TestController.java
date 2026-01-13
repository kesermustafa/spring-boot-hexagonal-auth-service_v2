package com.example.jwt_hexagonal_v2.adapter.in.web;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class TestController {

    @GetMapping("/user/hello")
    public String userHello() {
        return "USER or ADMIN OK";
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin/hello")
    public String adminHello() {
        return "ADMIN OK";
    }
}

