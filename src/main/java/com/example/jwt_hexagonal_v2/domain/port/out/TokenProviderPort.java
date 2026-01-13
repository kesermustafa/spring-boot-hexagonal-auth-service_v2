package com.example.jwt_hexagonal_v2.domain.port.out;

import java.util.UUID;

public interface TokenProviderPort {
    String generateAccessToken(UUID userId, String email, String role);
    long refreshTokenExpiration();
}
