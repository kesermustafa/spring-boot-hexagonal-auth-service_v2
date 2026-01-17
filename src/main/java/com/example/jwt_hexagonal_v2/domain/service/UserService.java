package com.example.jwt_hexagonal_v2.domain.service;

import com.example.jwt_hexagonal_v2.adapter.in.web.dto.RegisterRequest;
import com.example.jwt_hexagonal_v2.domain.enums.AuthProvider;
import com.example.jwt_hexagonal_v2.domain.enums.Role;
import com.example.jwt_hexagonal_v2.domain.exception.EmailAlreadyExistsException;
import com.example.jwt_hexagonal_v2.domain.exception.UserNotFoundException;
import com.example.jwt_hexagonal_v2.domain.messages.ErrorMessages;
import com.example.jwt_hexagonal_v2.domain.model.User;
import com.example.jwt_hexagonal_v2.domain.port.in.UserUseCase;
import com.example.jwt_hexagonal_v2.domain.port.out.RefreshTokenPort;
import com.example.jwt_hexagonal_v2.domain.port.out.UserRepositoryPort;
import com.example.jwt_hexagonal_v2.security.SecurityUtils;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
@RequiredArgsConstructor
public class UserService implements UserUseCase {

    private final UserRepositoryPort userRepository;
    private final PasswordEncoder passwordEncoder;
    private final RefreshTokenPort refreshTokenPort;

    @Override
    @Transactional
    public User register(RegisterRequest request) {
        String normalizedEmail = normalizeEmail(request.email());
        String rawPassword = request.password();

        var existingOpt = userRepository.findByEmail(normalizedEmail);

        if (existingOpt.isEmpty()) {
            User newUser = User.builder()
                    .email(normalizedEmail)
                    .password(passwordEncoder.encode(rawPassword))
                    .role(Role.USER) // sende USER/ADMIN ise
                    .provider(AuthProvider.LOCAL)
                    .providerId(null)
                    .build();

            return userRepository.save(newUser);
        }

        User existing = existingOpt.get();

        if (existing.getProvider() == AuthProvider.GOOGLE) {

            existing.setEmail(normalizedEmail);

            existing.setPassword(passwordEncoder.encode(rawPassword));

            User saved = userRepository.save(existing);

            refreshTokenPort.deleteAllByUserId(existing.getId());
            refreshTokenPort.flush();

            return saved;
        }

        throw new EmailAlreadyExistsException(
                String.format(ErrorMessages.EMAIL_ALREADY_EXIST_MESSAGE, normalizedEmail)
        );
    }

    private String normalizeEmail(String email) {
        if (email == null) return null;
        return email.trim().toLowerCase();
    }

    @Override
    public User findById(UUID id) {
        return userRepository.findById(id)
                .orElseThrow(() ->
                        new UserNotFoundException(String.format(ErrorMessages.USER_NOT_FOUND, id))
                );
    }


    public User getCurrentUser() {
        String email = SecurityUtils.getCurrentUserEmail();
        return userRepository.findByEmail(email).orElseThrow(() ->
                new UserNotFoundException(String.format(ErrorMessages.USER_NOT_FOUND, email))
        );
    }

}

