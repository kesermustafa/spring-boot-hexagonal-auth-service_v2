package com.example.jwt_hexagonal_v2.adapter.in.web.dto;

import jakarta.validation.constraints.NotBlank;

public record LinkGoogleRequest(
        @NotBlank String idToken
) {}
