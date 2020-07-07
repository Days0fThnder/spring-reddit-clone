package com.example.springredditclone.exception;

public class PostNotFoundException extends RuntimeException {

    public PostNotFoundException(String message) {
        super(message);
    }

    public PostNotFoundException(String message, Exception e) {
        super(message, e);
    }
}
