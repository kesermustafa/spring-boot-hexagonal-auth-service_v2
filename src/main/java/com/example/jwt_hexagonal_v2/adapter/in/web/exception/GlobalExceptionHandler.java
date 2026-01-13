package com.example.jwt_hexagonal_v2.adapter.in.web.exception;


import com.example.jwt_hexagonal_v2.domain.exception.*;
import com.example.jwt_hexagonal_v2.domain.messages.ErrorMessages;
import io.jsonwebtoken.MalformedJwtException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.stream.Collectors;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler extends ResponseEntityExceptionHandler {


    @Override
    protected ResponseEntity<Object> handleMethodArgumentNotValid(
            MethodArgumentNotValidException ex,
            HttpHeaders headers,
            HttpStatusCode status,
            WebRequest request) {

        log.error("Validation error: {}", ex.getMessage());

        Map<String, String> errors = ex.getBindingResult()
                .getFieldErrors()
                .stream()
                .collect(Collectors.toMap(
                        FieldError::getField,
                        error -> error.getDefaultMessage() != null ? error.getDefaultMessage() : "Geçersiz değer",
                        (existing, replacement) -> existing
                ));

        ErrorResponse error = ErrorResponse.builder()
                .status(HttpStatus.BAD_REQUEST.value())
                .code(HttpStatus.BAD_REQUEST.getReasonPhrase())
                .message("Validasyon hatası")
                .path(extractPath(request))
                .requestId(getRequestId(request))
                .timestamp(Instant.now())
                .details(errors)
                .build();

        return ResponseEntity
                .status(HttpStatus.BAD_REQUEST)
                .body(error);
    }

    @Override
    protected ResponseEntity<Object> handleHttpMessageNotReadable(
            HttpMessageNotReadableException ex,
            HttpHeaders headers,
            HttpStatusCode status,
            WebRequest request) {

        log.error("Message not readable: {}", ex.getMessage());

        ErrorResponse error = ErrorResponse.builder()
                .status(HttpStatus.BAD_REQUEST.value())
                .code(HttpStatus.BAD_REQUEST.getReasonPhrase())
                .message("Geçersiz veya eksik request body")
                .path(extractPath(request))
                .requestId(getRequestId(request))
                .timestamp(Instant.now())
                .build();

        return ResponseEntity
                .status(HttpStatus.BAD_REQUEST)
                .body(error);
    }


    @Override
    protected ResponseEntity<Object> handleMissingServletRequestParameter(
            MissingServletRequestParameterException ex,
            HttpHeaders headers,
            HttpStatusCode status,
            WebRequest request) {

        log.error("Missing parameter: {}", ex.getMessage());

        ErrorResponse error = ErrorResponse.builder()
                .status(HttpStatus.BAD_REQUEST.value())
                .code(HttpStatus.BAD_REQUEST.getReasonPhrase())
                .message(String.format("Zorunlu parametre eksik: '%s'", ex.getParameterName()))
                .path(extractPath(request))
                .requestId(getRequestId(request))
                .timestamp(Instant.now())
                .build();

        return ResponseEntity
                .status(HttpStatus.BAD_REQUEST)
                .body(error);
    }


    @ExceptionHandler(EmailAlreadyExistsException.class)
    public ResponseEntity<Object> handleEmailExists(
            EmailAlreadyExistsException ex, WebRequest request) {

        log.warn("Email already exists: {}", ex.getMessage());
        return buildError(HttpStatus.CONFLICT, ex.getMessage(), request);
    }

    @ExceptionHandler(ConflictException.class)
    public ResponseEntity<Object> handleConflict(
            ConflictException ex, WebRequest request) {

        log.warn("Conflict: {}", ex.getMessage());
        return buildError(HttpStatus.CONFLICT, ex.getMessage(), request);
    }

    @ExceptionHandler(UserNotFoundException.class)
    public ResponseEntity<Object> handleUserNotFound(UserNotFoundException ex, WebRequest request) {
       return buildError(HttpStatus.NOT_FOUND, ex.getMessage(), request);
    }

    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<Object> handleResourceNotFound(
            ResourceNotFoundException ex, WebRequest request) {

        log.warn("Resource not found: {}", ex.getMessage());
        return buildError(HttpStatus.NOT_FOUND, ex.getMessage(), request);
    }

    @ExceptionHandler(SecurityViolationException.class)
    public ResponseEntity<Object> handleSecurityViolation(
            SecurityViolationException ex, WebRequest request) {

        log.error("Security violation: {}", ex.getMessage());
        return buildError(HttpStatus.UNAUTHORIZED, ex.getMessage(), request);
    }

    @ExceptionHandler(BadRequestException.class)
    public ResponseEntity<Object> handleBadRequest(
            BadRequestException ex, WebRequest request) {

        log.warn("Bad request: {}", ex.getMessage());
        return buildError(HttpStatus.BAD_REQUEST, ex.getMessage(), request);
    }


    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<Object> handleAccessDeniedException(
            AccessDeniedException ex, WebRequest request) {

        log.warn("Access denied: {}", ex.getMessage());
        return buildError(HttpStatus.FORBIDDEN, "Bu işlem için yetkiniz yok", request);
    }


    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<Object> handleAuthenticationException(
            AuthenticationException ex, WebRequest request) {

        log.warn("Authentication failed: {}", ex.getMessage());
        return buildError(HttpStatus.UNAUTHORIZED, "Kimlik doğrulama başarısız", request);
    }

    @ExceptionHandler(RefreshTokenExpiredException.class)
    public ResponseEntity<Object> handleRefreshTokenExpired(
            RefreshTokenExpiredException ex, WebRequest request
    ) {
        return buildError(HttpStatus.UNAUTHORIZED, ErrorMessages.REFRESH_TOKEN_EXPIRED, request);
    }


    @ExceptionHandler(MethodArgumentTypeMismatchException.class)
    public ResponseEntity<Object> handleMethodArgumentTypeMismatch(
            MethodArgumentTypeMismatchException ex, WebRequest request) {

        log.error("Method argument type mismatch: {}", ex.getMessage());

        String message = String.format(
                "'%s' parametresi için geçersiz tip. Beklenen: %s",
                ex.getName(),
                ex.getRequiredType() != null ? ex.getRequiredType().getSimpleName() : "bilinmiyor"
        );

        return buildError(HttpStatus.BAD_REQUEST, message, request);
    }

    @ExceptionHandler(InvalidRefreshTokenException.class)
    public ResponseEntity<Object> handleInvalidRefreshToken(
            InvalidRefreshTokenException ex,
            WebRequest request) {

        return buildError(
                HttpStatus.UNAUTHORIZED,
                ex.getMessage(),
                request
        );
    }

    @ExceptionHandler(MalformedJwtException.class)
    public ResponseEntity<Object> handleMalformedJwt(
            MalformedJwtException ex, WebRequest request) {

        log.warn("Malformed JWT: {}", ex.getMessage());
        return buildError(
                HttpStatus.UNAUTHORIZED,
                "Geçersiz token formatı",
                request
        );
    }


    @ExceptionHandler(Exception.class)
    public ResponseEntity<Object> handleGenericException(
            Exception ex, WebRequest request) {

        log.error("Unexpected error occurred", ex);

        ErrorResponse error = ErrorResponse.builder()
                .status(HttpStatus.INTERNAL_SERVER_ERROR.value())
                .code(HttpStatus.INTERNAL_SERVER_ERROR.getReasonPhrase())
                .message("Bir hata oluştu. Lütfen daha sonra tekrar deneyin.")
                .path(extractPath(request))
                .timestamp(Instant.now())
                .requestId(getRequestId(request))
                .build();

        return ResponseEntity
                .status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(error);
    }

    private ResponseEntity<Object> buildError(
            HttpStatus status,
            String message,
            WebRequest request
    ) {
        return ResponseEntity.status(status)
                .body(ErrorResponse.builder()
                        .status(status.value())
                        .code(status.getReasonPhrase())
                        .message(message)
                        .path(extractPath(request))
                        .requestId(getRequestId(request))
                        .timestamp(Instant.now())
                        .build());
    }


    private String extractPath(WebRequest request) {
        return request.getDescription(false).replace("uri=", "");
    }


    private String getRequestId(WebRequest request) {
        Object id = ((ServletWebRequest) request)
                .getRequest()
                .getAttribute("requestId");
        return id != null ? id.toString() : null;
    }
}