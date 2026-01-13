package com.example.jwt_hexagonal_v2.adapter.out.persistence.adapter;

import com.example.jwt_hexagonal_v2.adapter.out.persistence.jpa.RefreshTokenJpaRepository;
import com.example.jwt_hexagonal_v2.domain.model.RefreshToken;
import com.example.jwt_hexagonal_v2.domain.port.out.RefreshTokenPort;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Component
@RequiredArgsConstructor
public class RefreshTokenPersistenceAdapter implements RefreshTokenPort {

    private final RefreshTokenJpaRepository repository;


    @Override
    public Optional<RefreshToken> findValidByToken(String token, Instant now) {
        return repository.findByTokenAndUsedFalseAndExpiryDateAfter(token, now);
    }

    @Override
    public Optional<RefreshToken> findByToken(String token) {
        return repository.findByToken(token);
    }

    @Override
    public RefreshToken save(RefreshToken refreshToken) {
        return repository.save(refreshToken);
    }

    @Override
    public void delete(RefreshToken refreshToken) {
        repository.delete(refreshToken);
    }

    @Override
    public void deleteAllByUserId(UUID userId) {
        repository.deleteAllByUser_Id(userId);
    }

    @Override
    public void flush() {
        repository.flush();
    }
}
