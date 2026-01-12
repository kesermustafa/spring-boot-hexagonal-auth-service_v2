package com.example.jwt_hexagonal_v2.adapter.in.web.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.CONFLICT)
public class ConflictException extends RuntimeException{

    public ConflictException(String message){
        super(message);

    }

}
