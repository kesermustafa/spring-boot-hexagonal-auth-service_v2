package com.example.jwt_hexagonal_v2.domain.service;

import com.example.jwt_hexagonal_v2.domain.enums.AuthProvider;
import com.example.jwt_hexagonal_v2.domain.enums.Role;
import com.example.jwt_hexagonal_v2.domain.exception.*;
import com.example.jwt_hexagonal_v2.domain.messages.ErrorMessages;
import com.example.jwt_hexagonal_v2.domain.model.RefreshToken;
import com.example.jwt_hexagonal_v2.domain.model.User;
import com.example.jwt_hexagonal_v2.domain.port.in.AuthUseCase;
import com.example.jwt_hexagonal_v2.domain.port.out.RefreshTokenPort;
import com.example.jwt_hexagonal_v2.domain.port.out.UserRepositoryPort;
import com.example.jwt_hexagonal_v2.domain.service.dto.AuthResponse;
import com.example.jwt_hexagonal_v2.infrastructure.security.GoogleTokenVerifierService;
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
    private final GoogleTokenVerifierService googleTokenVerifierService;

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

        if (rawRefreshToken == null || rawRefreshToken.isBlank()) {
            throw new InvalidRefreshTokenException(ErrorMessages.INVALID_REFRESH_TOKEN);
        }

        String encrypted = cryptoService.encrypt(rawRefreshToken);
        Instant now = Instant.now();

        // ✅ 1) Token’ı kilitleyerek oku (race condition engeli)
        RefreshToken token = refreshTokenPort.lockByToken(encrypted)
                .orElseThrow(() -> new InvalidRefreshTokenException(ErrorMessages.INVALID_REFRESH_TOKEN));

        // ✅ 2) Expired mı?
        if (token.getExpiryDate().isBefore(now)) {
            throw new RefreshTokenExpiredException(ErrorMessages.REFRESH_TOKEN_EXPIRED);
        }

        // ✅ 3) One-time use kontrolü (reuse)
        if (token.isUsed()) {
            handleReuseAttack(token.getUser().getId());
            throw new SecurityViolationException(ErrorMessages.REFRESH_TOKEN_REUSE_DETECTED);
        }

        // ✅ 4) Consume et
        token.setUsed(true);
        refreshTokenPort.save(token);
        refreshTokenPort.flush();

        // ✅ 5) Rotate: yeni access + yeni refresh üret
        return createTokens(token.getUser());
    }


/*    @Override
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
    }*/


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
                .user(user)
                .expiryDate(Instant.now().plusSeconds(jwtProperties.refreshTokenExpiration()))
                .used(false)
                .build();

     /* //  user.addRefreshToken(refreshToken);*/

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

    @Transactional
    public AuthResponse loginWithGoogle(String idToken) {

        var payload = googleTokenVerifierService.verify(idToken);

        String email = payload.getEmail();
        boolean emailVerified = Boolean.TRUE.equals(payload.getEmailVerified());
        String sub = payload.getSubject();

        if (!emailVerified) throw new InvalidGoogleTokenException("Google email is not verified");
        if (email == null || email.isBlank()) throw new InvalidGoogleTokenException("Google email missing");
        if (sub == null || sub.isBlank()) throw new InvalidGoogleTokenException("Google sub missing");

        final String normalizedEmail = email.trim().toLowerCase();

        // 1) Önce Google kimliği ile ara
        User user = userRepository.findByProviderAndProviderId(AuthProvider.GOOGLE, sub)
                .orElseGet(() -> {
                    // 2) Yoksa email ile ara (LOCAL hesap olabilir)
                    return userRepository.findByEmail(normalizedEmail)
                            .map(existing -> {
                                // Bu email zaten var → linkle
                                if (existing.getProvider() == AuthProvider.LOCAL || existing.getProvider() == null) {
                                    existing.setProvider(AuthProvider.GOOGLE);
                                    existing.setProviderId(sub);
                                    return userRepository.save(existing);
                                }
                                // Başka provider’a bağlıysa (örn Apple) politika senin:
                                // - izin verme
                                // - veya multi-provider tasarımına geç
                                throw new SecurityViolationException("Account is already linked to another provider");
                            })
                            .orElseGet(() -> {
                                // 3) Hiç yoksa yeni kullanıcı oluştur
                                User newUser = User.builder()
                                        .email(normalizedEmail)
                                        .password(passwordEncoder.encode(UUID.randomUUID().toString()))
                                        .role(Role.USER)
                                        .provider(AuthProvider.GOOGLE)
                                        .providerId(sub)
                                        .build();
                                return userRepository.save(newUser);
                            });
                });

        // Email sync (opsiyonel)
        if (!normalizedEmail.equalsIgnoreCase(user.getEmail())) {
            user.setEmail(normalizedEmail);
            userRepository.save(user);
        }

        refreshTokenPort.deleteAllByUserId(user.getId());
        refreshTokenPort.flush();

        return createTokens(user);
    }


    @Override
    @Transactional
    public void linkGoogleAccount(String currentUserEmail, String googleIdToken) {

        // 1️⃣ LOCAL user (zaten login olmuş)
        User user = userRepository.findByEmail(currentUserEmail)
                .orElseThrow(() -> new RuntimeException("User not found"));

        // 2️⃣ Zaten Google bağlıysa idempotent davran
        if (user.getProvider() == AuthProvider.GOOGLE && user.getProviderId() != null) {
            return;
        }

        // 3️⃣ Google token doğrula
        var payload = googleTokenVerifierService.verify(googleIdToken);

        String googleEmail = payload.getEmail();
        Boolean emailVerified = payload.getEmailVerified();
        String googleSub = payload.getSubject();

        if (!Boolean.TRUE.equals(emailVerified)) {
            throw new InvalidGoogleTokenException("Google email is not verified");
        }

        if (googleEmail == null || googleEmail.isBlank()) {
            throw new InvalidGoogleTokenException("Google email missing");
        }

        if (googleSub == null || googleSub.isBlank()) {
            throw new InvalidGoogleTokenException("Google subject missing");
        }

        // 4️⃣ Email güvenliği (aynı hesap mı?)
        String normalizedGoogleEmail = googleEmail.trim().toLowerCase();
        String normalizedLocalEmail = currentUserEmail.trim().toLowerCase();

        if (!normalizedGoogleEmail.equals(normalizedLocalEmail)) {
            throw new InvalidGoogleTokenException(
                    "Google account email does not match logged-in user email"
            );
        }

        // 5️⃣ Bu Google hesabı başka kullanıcıya bağlı mı?
        userRepository.findByProviderAndProviderId(AuthProvider.GOOGLE, googleSub)
                .ifPresent(other -> {
                    if (!other.getId().equals(user.getId())) {
                        throw new SecurityViolationException(
                                "This Google account is already linked to another user"
                        );
                    }
                });

        // 6️⃣ Link işlemi
        user.setProvider(AuthProvider.GOOGLE);
        user.setProviderId(googleSub);
        userRepository.save(user);

        // 7️⃣ Güvenlik: tüm refresh tokenları iptal et
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
