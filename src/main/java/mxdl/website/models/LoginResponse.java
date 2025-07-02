package mxdl.website.models;

public record LoginResponse (
        String message,
        String jwt
) {}
