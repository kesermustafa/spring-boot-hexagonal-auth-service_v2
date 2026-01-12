package com.example.jwt_hexagonal_v2.adapter.in.web.exception.messages;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class ErrorResponse {
    private int status;
    private String error;
    private String message;
    private String path;
    private String timestamp;
    private String requestId;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    private Object details;
}