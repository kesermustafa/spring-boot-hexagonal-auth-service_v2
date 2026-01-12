package com.example.jwt_hexagonal_v2.adapter.out.persistence.jpa;


import com.example.jwt_hexagonal_v2.domain.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface UserJpaRepository extends JpaRepository<User, UUID> {

    Optional<User> findByEmail(String email);

    boolean existsByEmail(String email);
}
