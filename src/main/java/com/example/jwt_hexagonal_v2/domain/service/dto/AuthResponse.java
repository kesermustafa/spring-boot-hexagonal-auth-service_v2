package com.example.jwt_hexagonal_v2.domain.service.dto;

import lombok.Builder;

@Builder
public record AuthResponse(
        String accessToken,
        String refreshToken
) {}
