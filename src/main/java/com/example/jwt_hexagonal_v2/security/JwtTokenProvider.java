package com.example.jwt_hexagonal_v2.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Date;
import java.util.UUID;

@Component
@RequiredArgsConstructor
public class JwtTokenProvider {

    private final JwtProperties jwtProperties;
    private Key key;

    @PostConstruct
    void init() {
        key = Keys.hmacShaKeyFor(jwtProperties.secret().getBytes());
    }

    public String generateAccessToken(UUID userId, String email, String role) {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + jwtProperties.accessTokenExpiration() );

        return Jwts.builder()
                .subject(userId.toString())
                .claim("email", email)
                .claim("role", role)
                .issuedAt(now)
                .expiration(expiry)
                .signWith(key)
                .compact();
    }

    public UUID getUserIdFromToken(String token) {
        return UUID.fromString(
                Jwts.parser()
                        .verifyWith((SecretKey) key)
                        .build()
                        .parseSignedClaims(token)
                        .getPayload()
                        .getSubject()
        );
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parser()
                    .verifyWith((SecretKey) key)
                    .build()
                    .parseSignedClaims(token);
            return true;
        } catch (JwtException | IllegalArgumentException ex) {
            return false;
        }
    }
}
