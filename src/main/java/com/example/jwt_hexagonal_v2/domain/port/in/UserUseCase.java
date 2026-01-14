package com.example.jwt_hexagonal_v2.domain.port.in;

import com.example.jwt_hexagonal_v2.adapter.in.web.dto.RegisterRequest;
import com.example.jwt_hexagonal_v2.domain.model.User;

import java.util.UUID;

public interface UserUseCase {
    User register(RegisterRequest registerRequest);
    User findById(UUID id);
}
