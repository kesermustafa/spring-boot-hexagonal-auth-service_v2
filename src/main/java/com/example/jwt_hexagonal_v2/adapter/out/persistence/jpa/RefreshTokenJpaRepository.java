package com.example.jwt_hexagonal_v2.adapter.out.persistence.jpa;

import com.example.jwt_hexagonal_v2.domain.model.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

public interface RefreshTokenJpaRepository extends JpaRepository<RefreshToken, UUID> {

    Optional<RefreshToken> findByUser_Id(UUID userId);

    Optional<RefreshToken> findByToken(String token);

    void deleteByUser_Id(UUID userId);

    void deleteAllByUser_Id(UUID userId);


    Optional<RefreshToken>
    findByTokenAndUsedFalseAndExpiryDateAfter(
            String token,
            Instant expiryDate
    );

}
