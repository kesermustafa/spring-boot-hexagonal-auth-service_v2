package com.example.jwt_hexagonal_v2.adapter.in.web.exception;

public class SecurityViolationException extends RuntimeException {
    public SecurityViolationException(String message) {
        super(message);
    }
}

