package com.shiraku.javacodespringsecurity.service;

import com.shiraku.javacodespringsecurity.repository.UserRepository;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import com.shiraku.javacodespringsecurity.model.UserEntity;
@Service
public class OurUserDetailedService implements UserDetailsService {
    private final UserRepository userRepository;

    public OurUserDetailedService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserEntity user = userRepository.findByUsername(username);
        if (user == null) {
            throw new UsernameNotFoundException("User not found");
        }
        if (!user.isAccountNonLocked()) {
            throw new BadCredentialsException("Account is locked");
        }
        return user;
    }

    public void increaseFailedAttempts(UserEntity user) {
        user.setFailedLoginAttempts(user.getFailedLoginAttempts() + 1);
        if (user.getFailedLoginAttempts() >= 5) {
            user.setAccountNonLocked(false);
        }
        userRepository.save(user);
    }

    public void resetFailedAttempts(UserEntity user) {
        user.setFailedLoginAttempts(0);
        userRepository.save(user);
    }
}
