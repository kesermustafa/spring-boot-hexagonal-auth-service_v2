package com.example.jwt_hexagonal_v2.domain.port.out;


import com.example.jwt_hexagonal_v2.domain.model.RefreshToken;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

public interface RefreshTokenPort {

    Optional<RefreshToken> findByUserId(UUID userId);

    Optional<RefreshToken> findByToken(String token);

    RefreshToken save(RefreshToken refreshToken);

    void delete(RefreshToken refreshToken);

    void deleteByUserId(UUID userId);

    Optional<RefreshToken> findByTokenAndUsedFalseAndExpiryDateAfter(
            String token,
            Instant now
    );

    void deleteAllByUserId(UUID userId);

    void flush();
}

