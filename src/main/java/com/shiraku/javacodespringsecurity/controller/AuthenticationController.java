package com.shiraku.javacodespringsecurity.controller;

import com.shiraku.javacodespringsecurity.jwt.JWTUtils;
import com.shiraku.javacodespringsecurity.model.UserEntity;
import com.shiraku.javacodespringsecurity.repository.UserRepository;
import com.shiraku.javacodespringsecurity.service.OurUserDetailedService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class AuthenticationController {
    private final JWTUtils jwtUtils;
    private final OurUserDetailedService userDetailedService;
    private final UserRepository userRepository;

    public AuthenticationController(JWTUtils jwtUtils, OurUserDetailedService userDetailedService, UserRepository userRepository) {
        this.jwtUtils = jwtUtils;
        this.userDetailedService = userDetailedService;
        this.userRepository = userRepository;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestParam String username, @RequestParam String password) {
        UserEntity user = (UserEntity) userDetailedService.loadUserByUsername(username);
        if (user.getPassword().equals(password)) {
            userDetailedService.resetFailedAttempts(user);
            String token = jwtUtils.generateToken(user.getUsername(), user.getRole());
            return ResponseEntity.ok(token);
        } else {
            userDetailedService.increaseFailedAttempts(user);
            return ResponseEntity.status(401).body("Invalid credentials");
        }
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(@RequestParam String refreshToken) {
        String username = jwtUtils.extractUsername(refreshToken);
        UserEntity user = (UserEntity) userDetailedService.loadUserByUsername(username);
        if (jwtUtils.isTokenValid(refreshToken, user.getPassword())) {
            String newToken = jwtUtils.generateToken(user.getUsername(), user.getRole());
            return ResponseEntity.ok(newToken);
        }
        return ResponseEntity.status(401).body("Invalid or expired token");
    }
}
