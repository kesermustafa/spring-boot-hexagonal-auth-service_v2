package com.example.jwt_hexagonal_v2.infrastructure.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties(GoogleProperties.class)
public class GoogleConfig {
}

