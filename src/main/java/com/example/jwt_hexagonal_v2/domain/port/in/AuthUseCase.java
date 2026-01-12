package com.example.jwt_hexagonal_v2.domain.port.in;

import com.example.jwt_hexagonal_v2.domain.service.dto.AuthResponse;

public interface AuthUseCase {

    AuthResponse login(String email, String password);

    AuthResponse refresh(String refreshToken);

    void logout(String refreshToken);

    void logoutAllDevices(String email);
}
