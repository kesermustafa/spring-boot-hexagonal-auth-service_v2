package com.example.jwt_hexagonal_v2.adapter.out.persistence.jpa;

import com.example.jwt_hexagonal_v2.domain.model.RefreshToken;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

public interface RefreshTokenJpaRepository extends JpaRepository<RefreshToken, UUID> {

    Optional<RefreshToken> findByToken(String token);

    void deleteAllByUser_Id(UUID userId);

    Optional<RefreshToken> findByTokenAndUsedFalseAndExpiryDateAfter(String token, Instant now);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select r from RefreshToken r where r.token = :token")
    Optional<RefreshToken> lockByToken(@Param("token") String token);

}
