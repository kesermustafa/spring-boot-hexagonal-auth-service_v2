package com.example.jwt_hexagonal_v2.security;

import com.example.jwt_hexagonal_v2.domain.exception.SecurityViolationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.UUID;

public final class SecurityUtils {

    private SecurityUtils() {}

    public static UUID getCurrentUserId() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || authentication.getPrincipal() == null) {
            throw new SecurityViolationException("Unauthenticated access");
        }

        if (!(authentication.getPrincipal() instanceof UUID userId)) {
            throw new SecurityViolationException("Invalid authentication principal");
        }

        return userId;
    }


    public static String getCurrentUserEmail() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        assert authentication != null;
        return authentication.getName();
    }


}
