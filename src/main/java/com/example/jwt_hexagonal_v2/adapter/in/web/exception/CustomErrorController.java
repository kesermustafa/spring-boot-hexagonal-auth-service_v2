package com.example.jwt_hexagonal_v2.adapter.in.web.exception;



import jakarta.servlet.http.HttpServletRequest;
import org.springframework.boot.webmvc.error.ErrorController;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.time.LocalDateTime;

@RestController
public class CustomErrorController implements ErrorController {

    @RequestMapping("/error")
    public ResponseEntity<ErrorResponse> handleError(HttpServletRequest request) {

        Object statusCode = request.getAttribute("jakarta.servlet.error.status_code");
        Object path = request.getAttribute("jakarta.servlet.error.request_uri");

        int status = statusCode != null
                ? Integer.parseInt(statusCode.toString())
                : 500;

        HttpStatus httpStatus = HttpStatus.valueOf(status);

        ErrorResponse error = ErrorResponse.builder()
                .status(httpStatus.value())
                .code(httpStatus.getReasonPhrase())
                .message(httpStatus == HttpStatus.NOT_FOUND
                        ? "Endpoint bulunamadı"
                        : "Bir hata oluştu")
                .path(path != null ? path.toString() : "")
                .timestamp(Instant.now())
                .build();

        return ResponseEntity.status(httpStatus).body(error);
    }
}
