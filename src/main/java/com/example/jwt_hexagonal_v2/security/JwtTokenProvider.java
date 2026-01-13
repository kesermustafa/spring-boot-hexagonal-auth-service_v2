package com.example.jwt_hexagonal_v2.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.UUID;

@Component
public class JwtTokenProvider {

    private final JwtProperties props;
    private final SecretKey accessKey;

    public JwtTokenProvider(JwtProperties props) {
        this.props = props;
        this.accessKey = Keys.hmacShaKeyFor(props.secret().getBytes(StandardCharsets.UTF_8));
    }

    public String generateAccessToken(UUID userId, String email, String role) {
        long now = System.currentTimeMillis();
        Date issuedAt = new Date(now);
        Date expiresAt = new Date(now + props.accessTokenExpiration());

        return Jwts.builder()
                .subject(userId.toString())
                .claim("email", email)
                .claim("role", role) // "USER" / "ADMIN"
                .issuedAt(issuedAt)
                .expiration(expiresAt)
                .signWith(accessKey, Jwts.SIG.HS256)
                .compact();
    }

    public boolean validateToken(String token) {
        try {
            parseClaims(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    public UUID getUserIdFromToken(String token) {
        String sub = parseClaims(token).getSubject();
        return UUID.fromString(sub);
    }

    public String getRoleFromToken(String token) {
        Object role = parseClaims(token).get("role");
        return role == null ? null : role.toString(); // "USER" / "ADMIN"
    }

    public String getEmailFromToken(String token) {
        Object email = parseClaims(token).get("email");
        return email == null ? null : email.toString();
    }

    private Claims parseClaims(String token) {
        return Jwts.parser()
                .verifyWith(accessKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}
