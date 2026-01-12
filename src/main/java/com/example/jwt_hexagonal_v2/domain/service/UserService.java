package com.example.jwt_hexagonal_v2.domain.service;

import com.example.jwt_hexagonal_v2.domain.enums.Role;
import com.example.jwt_hexagonal_v2.domain.model.User;
import com.example.jwt_hexagonal_v2.domain.port.in.UserUseCase;
import com.example.jwt_hexagonal_v2.domain.port.out.UserRepositoryPort;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService implements UserUseCase {

    private final UserRepositoryPort userRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void register(String email, String password) {

        if (userRepository.existsByEmail(email)) {
            throw new RuntimeException("Email already exists");
        }

        User user = User.builder()
                .email(email)
                .password(passwordEncoder.encode(password))
                .role(Role.USER)
                .build();

        userRepository.save(user);
    }
}

