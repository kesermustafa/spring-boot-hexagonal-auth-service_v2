package com.example.jwt_hexagonal_v2.adapter.in.web.dto.response;

import java.util.UUID;

public record UserResponse(
        UUID id,
        String email,
        String role,
        boolean enabled
) {
}
