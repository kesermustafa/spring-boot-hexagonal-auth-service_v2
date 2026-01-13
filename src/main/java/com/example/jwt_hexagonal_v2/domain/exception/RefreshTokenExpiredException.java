package com.example.jwt_hexagonal_v2.domain.exception;

public class RefreshTokenExpiredException extends RuntimeException {

    public RefreshTokenExpiredException() {
        super("Refresh token expired");
    }

    public RefreshTokenExpiredException(String message) {
        super(message);
    }
}
