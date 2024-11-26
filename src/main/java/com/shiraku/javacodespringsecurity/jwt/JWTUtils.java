package com.shiraku.javacodespringsecurity.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import com.shiraku.javacodespringsecurity.model.UserEntity;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
public class JWTUtils {
    private static final String SECRET_KEY = "secretKey12345";
    private static final long EXPIRATION_TIME = 86400000; // 24 hours

    public String generateToken(String username, UserEntity.Role role) {
        return JWT.create()
                .withSubject(username).withClaim("role", role.toString())
                .withIssuedAt(new Date())
                .withExpiresAt(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .sign(Algorithm.HMAC256(SECRET_KEY));
    }

    public String extractUsername(String token) {
        return extractClaim(token, "sub");
    }

    public String extractRole(String token) {
        return extractClaim(token, "role");
    }

    private String extractClaim(String token, String claimKey) {
        DecodedJWT decodedJWT = decodeToken(token);
        return decodedJWT.getClaim(claimKey).asString();
    }

    private DecodedJWT decodeToken(String token) {
        JWTVerifier verifier = JWT.require(Algorithm.HMAC256(SECRET_KEY))
                .build();
        return verifier.verify(token);
    }

    public boolean isTokenValid(String token, String username) {
        return (username.equals(extractUsername(token)) && !isTokenExpired(token));
    }

    public boolean isTokenExpired(String token) {
        DecodedJWT decodedJWT = decodeToken(token);
        return decodedJWT.getExpiresAt().before(new Date());
    }
}
