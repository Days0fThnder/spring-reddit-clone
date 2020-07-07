package com.example.springredditclone.controller;

import com.example.springredditclone.exception.CustomErrorResponse;
import com.example.springredditclone.exception.TokenException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import java.time.LocalDateTime;

@ControllerAdvice
public class CustomerRestExceptionHandler {
    @ExceptionHandler({TokenException.class})
    public ResponseEntity<CustomErrorResponse> tokenValidationError(Exception ex) {
        CustomErrorResponse errors = new CustomErrorResponse();
        errors.setTimestamp(LocalDateTime.now());
        errors.setError(ex.getMessage());
        errors.setStatus(HttpStatus.UNAUTHORIZED.value());

        return new ResponseEntity<>(errors, HttpStatus.UNAUTHORIZED);
    }
}
