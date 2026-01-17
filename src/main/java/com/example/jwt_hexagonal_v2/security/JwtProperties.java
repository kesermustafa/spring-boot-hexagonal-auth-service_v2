package com.example.jwt_hexagonal_v2.security;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "security.jwt")
public record JwtProperties(
        String secret,
        String refreshSecret,
        long accessTokenExpiration,
        long refreshTokenExpiration
) {}
