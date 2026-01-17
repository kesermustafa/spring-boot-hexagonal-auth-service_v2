package com.example.jwt_hexagonal_v2.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenProvider jwtTokenProvider;

    public JwtAuthenticationFilter(JwtTokenProvider jwtTokenProvider) {
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String authHeader = request.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = authHeader.substring(7).trim();
        if (token.isBlank() || !jwtTokenProvider.validateToken(token)) {
            filterChain.doFilter(request, response);
            return;
        }

        UUID userId = jwtTokenProvider.getUserIdFromToken(token);
        String role = jwtTokenProvider.getRoleFromToken(token);

        List<GrantedAuthority> authorities = Collections.emptyList();
        if (role != null && !role.isBlank()) {
            String normalized = role.startsWith("ROLE_") ? role : "ROLE_" + role;
            authorities = List.of(new SimpleGrantedAuthority(normalized));
        }

        var authentication = new UsernamePasswordAuthenticationToken(userId, null, authorities);
        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        SecurityContextHolder.getContext().setAuthentication(authentication);

        filterChain.doFilter(request, response);
    }


/*    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        // Zaten Authentication set edilmişse tekrar uğraşma
        if (SecurityContextHolder.getContext().getAuthentication() != null) {
            filterChain.doFilter(request, response);
            return;
        }

        String authHeader = request.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = authHeader.substring(7).trim();
        if (token.isBlank()) {
            filterChain.doFilter(request, response);
            return;
        }

        if (!jwtTokenProvider.validateToken(token)) {
            filterChain.doFilter(request, response);
            return;
        }

        UUID userId = jwtTokenProvider.getUserIdFromToken(token);

        // Token içinden role okuma (senin kullandığın şekilde)
        String role = jwtTokenProvider.getRoleFromToken(token); // "USER" / "ADMIN"
        List<GrantedAuthority> authorities =
                (role == null || role.isBlank())
                        ? Collections.emptyList()
                        : Collections.singletonList(new SimpleGrantedAuthority("ROLE_" + role));

        var authentication = new UsernamePasswordAuthenticationToken(
                userId,    // ✅ principal = UUID
                null,
                authorities
        );

        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        SecurityContextHolder.getContext().setAuthentication(authentication);

        filterChain.doFilter(request, response);
    }*/

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getServletPath();

        // ✅ /api/auth/google/link JWT gerektiriyor → filter'dan MUAF OLMASIN
        if (path.equals("/api/auth/google/link")) {
            return false;
        }

        // ✅ Diğer auth endpointleri muaf (register/login/google-login/refresh vs.)
        return path.startsWith("/api/auth/");
    }
}
