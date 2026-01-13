package com.example.jwt_hexagonal_v2.domain.port.out;

import com.example.jwt_hexagonal_v2.domain.model.RefreshToken;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

public interface RefreshTokenPort {

       Optional<RefreshToken> findValidByToken(String token, Instant now);

    Optional<RefreshToken> findByToken(String token); // logout gibi yerlerde lazım olabilir

    RefreshToken save(RefreshToken refreshToken);

    void delete(RefreshToken refreshToken);

    void deleteAllByUserId(UUID userId);
    Optional<RefreshToken> findByTokenAndUsedFalseAndExpiryDateAfter(String token, Instant now);

    Optional<RefreshToken> lockByToken(String token);

    void flush();
}


