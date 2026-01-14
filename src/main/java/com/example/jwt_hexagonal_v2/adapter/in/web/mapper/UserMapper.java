package com.example.jwt_hexagonal_v2.adapter.in.web.mapper;

import com.example.jwt_hexagonal_v2.adapter.in.web.dto.response.UserResponse;
import com.example.jwt_hexagonal_v2.domain.model.User;

public final class UserMapper {

    private UserMapper() {}

    public static UserResponse toResponse(User user) {
        return new UserResponse(
                user.getId(),
                user.getEmail(),
                user.getRole().name(),
                user.isEnabled()
        );
    }
}
