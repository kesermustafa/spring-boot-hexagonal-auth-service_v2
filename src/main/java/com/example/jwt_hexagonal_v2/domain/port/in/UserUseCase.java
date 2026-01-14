package com.example.jwt_hexagonal_v2.domain.port.in;

import com.example.jwt_hexagonal_v2.adapter.in.web.dto.RegisterRequest;
import com.example.jwt_hexagonal_v2.domain.model.User;

public interface UserUseCase {
    User register(RegisterRequest registerRequest);
}
