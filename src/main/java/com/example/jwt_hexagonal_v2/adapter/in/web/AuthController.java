package com.example.jwt_hexagonal_v2.adapter.in.web;

import com.example.jwt_hexagonal_v2.adapter.in.web.dto.AuthResponseDto;
import com.example.jwt_hexagonal_v2.adapter.in.web.dto.LoginRequest;
import com.example.jwt_hexagonal_v2.adapter.in.web.dto.RefreshTokenRequest;
import com.example.jwt_hexagonal_v2.adapter.in.web.dto.RegisterRequest;
import com.example.jwt_hexagonal_v2.domain.port.in.AuthUseCase;
import com.example.jwt_hexagonal_v2.domain.port.in.UserUseCase;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthUseCase authUseCase;
    private final UserUseCase userUseCase;

    @PostMapping("/register")
    public ResponseEntity<Void> register(
            @RequestBody @Valid RegisterRequest request
    ) {
        userUseCase.register(request.email(), request.password());
        return ResponseEntity.status(HttpStatus.CREATED).build();
    }


    @PostMapping("/login")
    public ResponseEntity<AuthResponseDto> login(
            @RequestBody @Valid LoginRequest request
    ) {
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
    public ResponseEntity<AuthResponseDto> refresh(
            @RequestBody @Valid RefreshTokenRequest request
    ) {
        var result = authUseCase.refresh(request.refreshToken());

        return ResponseEntity.ok(
                new AuthResponseDto(
                        result.accessToken(),
                        result.refreshToken()
                )
        );
    }


    @PostMapping("/logout-all")
    public ResponseEntity<Void> logoutAllDevices(
            @AuthenticationPrincipal UserDetails userDetails
    ) {
        authUseCase.logoutAllDevices(userDetails.getUsername());
        return ResponseEntity.noContent().build();
    }

}
