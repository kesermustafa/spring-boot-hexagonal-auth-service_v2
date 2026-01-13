package com.example.jwt_hexagonal_v2.domain.exception;

public class InvalidGoogleTokenException extends RuntimeException {
    public InvalidGoogleTokenException(String msg) { super(msg); }
}

