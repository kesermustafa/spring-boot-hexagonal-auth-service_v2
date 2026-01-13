package com.example.jwt_hexagonal_v2.infrastructure.security;

import com.example.jwt_hexagonal_v2.infrastructure.config.GoogleProperties;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.jackson2.JacksonFactory;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Collections;

@Service
@RequiredArgsConstructor
public class GoogleTokenVerifierService {

    private final GoogleProperties googleProperties;


    private static String base64UrlDecode(String part) {
        return new String(java.util.Base64.getUrlDecoder().decode(part));
    }

    public GoogleIdToken.Payload verify(String idTokenString) {

        try {
            if (idTokenString == null || idTokenString.isBlank()) {
                throw new RuntimeException("idToken is null/blank");
            }

            long dotCount = idTokenString.chars().filter(ch -> ch == '.').count();
            if (dotCount != 2) {
                throw new RuntimeException("Not a JWT id_token. dotCount=" + dotCount);
            }

            // ID token JWT format kontrolü (3 parça)
            if (idTokenString.chars().filter(ch -> ch == '.').count() != 2) {
                throw new RuntimeException("This is not an ID token JWT (expected 3 parts header.payload.signature)");
            }

            GoogleIdTokenVerifier verifier =
                    new GoogleIdTokenVerifier.Builder(
                            new NetHttpTransport(),
                            JacksonFactory.getDefaultInstance()
                    )
                            .setAudience(Collections.singletonList(googleProperties.clientId()))
                            .setIssuer("https://accounts.google.com") // opsiyonel ama iyi
                            .build();

            GoogleIdToken idToken = verifier.verify(idTokenString);

            if (idToken == null) {
                throw new RuntimeException("Invalid Google ID Token (verification returned null). " +
                        "Most likely: wrong client-id (aud mismatch), expired token, or not an ID token.");
            }

            return idToken.getPayload();

        } catch (Exception e) {
            throw new RuntimeException("Google token verification failed: " + e.getMessage(), e);
        }
    }
}
