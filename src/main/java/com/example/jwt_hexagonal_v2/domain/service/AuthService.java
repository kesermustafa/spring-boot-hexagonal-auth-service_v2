package com.example.jwt_hexagonal_v2.domain.service;

import com.example.jwt_hexagonal_v2.adapter.in.web.exception.BadRequestException;
import com.example.jwt_hexagonal_v2.adapter.in.web.exception.UserNotFoundException;
import com.example.jwt_hexagonal_v2.adapter.in.web.exception.messages.ErrorMessages;
import com.example.jwt_hexagonal_v2.domain.model.RefreshToken;
import com.example.jwt_hexagonal_v2.domain.model.User;
import com.example.jwt_hexagonal_v2.domain.port.in.AuthUseCase;
import com.example.jwt_hexagonal_v2.domain.port.out.RefreshTokenPort;
import com.example.jwt_hexagonal_v2.domain.port.out.UserRepositoryPort;
import com.example.jwt_hexagonal_v2.domain.service.dto.AuthResponse;
import com.example.jwt_hexagonal_v2.security.JwtProperties;
import com.example.jwt_hexagonal_v2.security.JwtTokenProvider;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.UUID;


@Service
@RequiredArgsConstructor
@Transactional
public class AuthService implements AuthUseCase {

    private final UserRepositoryPort userRepository;
    private final JwtTokenProvider jwtTokenProvider;
    private final RefreshTokenCryptoService cryptoService;
    private final PasswordEncoder passwordEncoder;
    private final RefreshTokenPort refreshTokenPort;
    private final JwtProperties jwtProperties;

    @Override
    public AuthResponse login(String email, String password) {

        User user = getUserByEmailOrThrow(email);

        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new RuntimeException("Invalid credentials");
        }

        // ✅ TÜM CİHAZLARDAN LOGOUT
        refreshTokenPort.deleteAllByUserId(user.getId());
        refreshTokenPort.flush();

        return createTokens(user);
    }


    @Override
    @Transactional
    public AuthResponse refresh(String rawRefreshToken) {

        String encrypted = cryptoService.encrypt(rawRefreshToken);

        RefreshToken existing = refreshTokenPort.findByToken(encrypted)
                .orElseThrow(() ->
                        new RuntimeException("Invalid refresh token")
                );

        // 🔥 GERÇEK REUSE DETECTION
        if (existing.isUsed()) {
            handleReuseAttack(existing.getUser().getId());
            throw new RuntimeException("Refresh token reuse detected");
        }

        if (existing.getExpiryDate().isBefore(Instant.now())) {
            refreshTokenPort.delete(existing);
            refreshTokenPort.flush();
            throw new RuntimeException("Refresh token expired");
        }

        // ✅ TOKEN ARTIK KULLANILDI
        existing.setUsed(true);
        refreshTokenPort.save(existing);
        refreshTokenPort.flush();

        // ✅ YENİ TOKEN ÜRET
        return createTokens(existing.getUser());
    }



    @Override
    public void logout(String rawRefreshToken) {

        String encrypted = cryptoService.encrypt(rawRefreshToken);

        refreshTokenPort.findByToken(encrypted)
                .ifPresent(refreshTokenPort::delete);
    }

    private AuthResponse createTokens(User user) {

        String accessToken = jwtTokenProvider.generateAccessToken(
                user.getId(),
                user.getEmail(),
                user.getRole().name()
        );

        String rawRefreshToken = UUID.randomUUID().toString();
        String encryptedRefreshToken = cryptoService.encrypt(rawRefreshToken);

        RefreshToken refreshToken = RefreshToken.builder()
                .token(encryptedRefreshToken)
                .user(user)
                .expiryDate(
                        Instant.now().plusSeconds(jwtProperties.refreshTokenExpiration())
                )
                .used(false)
                .build();

        refreshTokenPort.save(refreshToken);

        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(rawRefreshToken)
                .build();
    }


    private void handleReuseAttack(UUID userId) {
        refreshTokenPort.deleteAllByUserId(userId);
        refreshTokenPort.flush();
    }


    @Override
    @Transactional
    public void logoutAllDevices(String email) {

        User user = getUserByEmailOrThrow(email);

        refreshTokenPort.deleteAllByUserId(user.getId());
        refreshTokenPort.flush();
    }


    private User getUserByEmailOrThrow(String email) {
        return userRepository.findByEmail(email)
                .orElseThrow(() ->
                        new UserNotFoundException(String.format(ErrorMessages.USER_NOT_FOUND, email))
                );
    }

}
