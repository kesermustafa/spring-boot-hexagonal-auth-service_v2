package com.example.jwt_hexagonal_v2.domain.port.out;


import com.example.jwt_hexagonal_v2.domain.enums.AuthProvider;
import com.example.jwt_hexagonal_v2.domain.model.User;

import java.util.Optional;
import java.util.UUID;

public interface UserRepositoryPort {

    Optional<User> findByEmail(String email);

    Optional<User> findById(UUID id);

    User save(User user);

    boolean existsByEmail(String email);

    Optional<User> findByProviderAndProviderId(AuthProvider provider, String providerId);
}
