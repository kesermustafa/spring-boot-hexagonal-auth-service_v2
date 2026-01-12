package com.example.jwt_hexagonal_v2.domain.port.in;

public interface UserUseCase {
    void register(String email, String password);
}
