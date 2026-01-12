package com.example.jwt_hexagonal_v2.adapter.out.persistence.adapter;


import com.example.jwt_hexagonal_v2.adapter.out.persistence.jpa.UserJpaRepository;
import com.example.jwt_hexagonal_v2.domain.model.User;
import com.example.jwt_hexagonal_v2.domain.port.out.UserRepositoryPort;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.Optional;
import java.util.UUID;

@Component
@RequiredArgsConstructor
public class UserPersistenceAdapter implements UserRepositoryPort {

    private final UserJpaRepository userJpaRepository;

    @Override
    public Optional<User> findByEmail(String email) {
        return userJpaRepository.findByEmail(email);
    }

    @Override
    public Optional<User> findById(UUID id) {
        return userJpaRepository.findById(id);
    }

    @Override
    public User save(User user) {
        return userJpaRepository.save(user);
    }

    @Override
    public boolean existsByEmail(String email) {
        return userJpaRepository.existsByEmail(email);
    }
}
