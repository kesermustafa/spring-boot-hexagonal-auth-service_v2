package com.example.jwt_hexagonal_v2.infrastructure.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "google")
public record GoogleProperties(
        String clientId
) {}
