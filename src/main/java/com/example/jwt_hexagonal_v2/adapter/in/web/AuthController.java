package com.example.jwt_hexagonal_v2.adapter.in.web;

import com.example.jwt_hexagonal_v2.adapter.in.web.dto.*;
import com.example.jwt_hexagonal_v2.adapter.in.web.dto.response.ApiResponse;
import com.example.jwt_hexagonal_v2.adapter.in.web.dto.response.UserResponse;
import com.example.jwt_hexagonal_v2.adapter.in.web.mapper.UserMapper;
import com.example.jwt_hexagonal_v2.domain.model.User;
import com.example.jwt_hexagonal_v2.domain.port.in.AuthUseCase;
import com.example.jwt_hexagonal_v2.domain.port.in.UserUseCase;
import com.example.jwt_hexagonal_v2.domain.port.out.UserRepositoryPort;
import com.example.jwt_hexagonal_v2.domain.service.dto.AuthResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthUseCase authUseCase;
    private final UserUseCase userUseCase;
    private final UserRepositoryPort userRepository;

    @PostMapping("/register")
    public ResponseEntity<ApiResponse<UserResponse>> register( @Valid @RequestBody RegisterRequest request) {

        User user = userUseCase.register(request);

        UserResponse response = UserMapper.toResponse(user);

        return ResponseEntity.ok(
                ApiResponse.success(
                        "User registered successfully",
                        response
                )
        );
    }


    @PostMapping("/login")
    public ResponseEntity<AuthResponseDto> login( @RequestBody @Valid LoginRequest request) {
        var result = authUseCase.login(
                request.email(),
                request.password()
        );

        return ResponseEntity.ok(
                new AuthResponseDto(
                        result.accessToken(),
                        result.refreshToken()
                )
        );
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponseDto> refresh( @RequestBody @Valid RefreshTokenRequest request ) {
        var result = authUseCase.refresh(request.refreshToken());

        return ResponseEntity.ok(
                new AuthResponseDto(
                        result.accessToken(),
                        result.refreshToken()
                )
        );
    }


    @PostMapping("/logout-all")
    public ResponseEntity<Void> logoutAllDevices( @AuthenticationPrincipal UserDetails userDetails ) {
        authUseCase.logoutAllDevices(userDetails.getUsername());
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/google")
    public ResponseEntity<AuthResponse> googleLogin(@RequestBody GoogleLoginRequest req) {
        return ResponseEntity.ok(authUseCase.loginWithGoogle(req.idToken()));
    }

    @PostMapping("/google/link")
    public ResponseEntity<Void> linkGoogle(@RequestBody @Valid LinkGoogleRequest request,
                                           Authentication authentication) {

        UUID userId = (UUID) authentication.getPrincipal();
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        authUseCase.linkGoogleAccount(user.getEmail(), request.idToken());

        return ResponseEntity.noContent().build();
    }


}
