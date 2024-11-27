package com.shiraku.javacodespringsecurity.controller;

import com.shiraku.javacodespringsecurity.dto.LoginRequest;
import com.shiraku.javacodespringsecurity.dto.RegisterRequest;
import com.shiraku.javacodespringsecurity.jwt.JWTUtils;
import com.shiraku.javacodespringsecurity.model.UserEntity;
import com.shiraku.javacodespringsecurity.repository.UserRepository;
import com.shiraku.javacodespringsecurity.service.OurUserDetailedService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Objects;

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

    @GetMapping("/home")
    public ResponseEntity<?> home() {
        return ResponseEntity.ok("Welcome to the home page!");
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequest user) {
        if (userRepository.existsByUsername(user.getUsername())) {
            return ResponseEntity.status(400).body("User already exists");
        }
        UserEntity newUser = new UserEntity();
        newUser.setUsername(user.getUsername());
        newUser.setPassword(user.getPassword());
        newUser.setRole(UserEntity.Role.valueOf(user.getRole()));
        userRepository.save(newUser);
        return ResponseEntity.ok("User registered successfully");
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest user) {
        UserEntity userEnt = (UserEntity) userDetailedService.loadUserByUsername(user.getUsername());
        if (!userEnt.isAccountNonLocked()) {return ResponseEntity.status(403).body("Account is locked");}
        if (user.getPassword().equals(userEnt.getPassword())) {
            userDetailedService.resetFailedAttempts(userEnt);
            String token = jwtUtils.generateToken(user.getUsername(), userEnt.getRole());
            return ResponseEntity.ok(token);
        } else {
            userDetailedService.increaseFailedAttempts(userEnt);
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
