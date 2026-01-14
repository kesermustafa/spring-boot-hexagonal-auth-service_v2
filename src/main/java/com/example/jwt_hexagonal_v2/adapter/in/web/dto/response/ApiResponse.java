package com.example.jwt_hexagonal_v2.adapter.in.web.dto.response;

public record ApiResponse<T>(
        boolean success,
        String message,
        T data
) {
    public static <T> ApiResponse<T> success(String message, T data) {

        return new ApiResponse<>(true, message, data);
    }
}
