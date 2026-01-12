package com.example.jwt_hexagonal_v2.adapter.in.web.dto;


public record AuthResponseDto(
        String accessToken,
        String refreshToken
) {}

