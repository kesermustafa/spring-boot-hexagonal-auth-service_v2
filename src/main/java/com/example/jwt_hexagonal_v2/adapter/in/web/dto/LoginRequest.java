package com.example.jwt_hexagonal_v2.adapter.in.web.dto;


import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record LoginRequest(

        @Email
        @NotBlank
        String email,

        @NotBlank
        String password
) {}

