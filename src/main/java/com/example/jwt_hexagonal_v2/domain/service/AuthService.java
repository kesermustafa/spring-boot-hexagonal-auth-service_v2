package com.example.jwt_hexagonal_v2.domain.service;

import com.example.jwt_hexagonal_v2.domain.exception.InvalidRefreshTokenException;
import com.example.jwt_hexagonal_v2.domain.exception.RefreshTokenExpiredException;
import com.example.jwt_hexagonal_v2.domain.exception.SecurityViolationException;
import com.example.jwt_hexagonal_v2.domain.exception.UserNotFoundException;
import com.example.jwt_hexagonal_v2.domain.messages.ErrorMessages;
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
import java.util.Optional;
import java.util.UUID;


@Service
@RequiredArgsConstructor

public class AuthService implements AuthUseCase {

    private final UserRepositoryPort userRepository;
    private final JwtTokenProvider jwtTokenProvider;
    private final RefreshTokenCryptoService cryptoService;
    private final PasswordEncoder passwordEncoder;
    private final RefreshTokenPort refreshTokenPort;
    private final JwtProperties jwtProperties;

    @Transactional
    @Override
    public AuthResponse login(String email, String password) {

        User user = getUserByEmailOrThrow(email);

        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new RuntimeException("Invalid credentials");
        }

        refreshTokenPort.deleteAllByUserId(user.getId());
        refreshTokenPort.flush();

        return createTokens(user);
    }


    @Override
    @Transactional
    public AuthResponse refresh(String rawRefreshToken) {

        String encrypted = cryptoService.encrypt(rawRefreshToken);
        Instant now = Instant.now();

        Optional<RefreshToken> validOpt =
                refreshTokenPort.findValidByToken(encrypted, now);

        if (validOpt.isPresent()) {
            RefreshToken valid = validOpt.get();

            valid.setUsed(true);
            refreshTokenPort.save(valid);
            refreshTokenPort.flush();

            return createTokens(valid.getUser());
        }

        RefreshToken existing = refreshTokenPort.findByToken(encrypted)
                .orElseThrow(() -> new InvalidRefreshTokenException(ErrorMessages.INVALID_REFRESH_TOKEN));

        // ✅ 3) DB'de var ama valid değil → reuse veya expired
        if (existing.isUsed()) {
            handleReuseAttack(existing.getUser().getId());
            throw new SecurityViolationException(ErrorMessages.REFRESH_TOKEN_REUSE_DETECTED);
        }


        throw new RefreshTokenExpiredException(ErrorMessages.REFRESH_TOKEN_EXPIRED);
    }




    @Transactional
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
                .expiryDate(Instant.now().plusSeconds(jwtProperties.refreshTokenExpiration()))
                .used(false)
                .build();

        user.addRefreshToken(refreshToken);
        refreshTokenPort.save(refreshToken);
        refreshTokenPort.flush();

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
