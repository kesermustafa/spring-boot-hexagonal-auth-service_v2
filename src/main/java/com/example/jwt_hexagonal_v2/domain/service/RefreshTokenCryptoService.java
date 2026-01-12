package com.example.jwt_hexagonal_v2.domain.service;

import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

@Component
public class RefreshTokenCryptoService {

    @Value("${security.jwt.secret}")
    private String secret;

    private SecretKeySpec keySpec;

    @PostConstruct
    void init() {
        byte[] key = secret.substring(0, 32).getBytes(); // AES-256
        this.keySpec = new SecretKeySpec(key, "AES");
    }

    public String encrypt(String rawToken) {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec);
            return Base64.getEncoder()
                    .encodeToString(cipher.doFinal(rawToken.getBytes()));
        } catch (Exception e) {
            throw new IllegalStateException("Refresh token encryption failed");
        }
    }
}

