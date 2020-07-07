package com.example.springredditclone.exception;

public class TokenException extends RuntimeException {
    public TokenException() {
        super("Token error ");
    }
}
