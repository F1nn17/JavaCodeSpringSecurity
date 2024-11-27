package com.shiraku.javacodespringsecurity.security;

import com.shiraku.javacodespringsecurity.filter.JwtAuthenticationFilter;
import com.shiraku.javacodespringsecurity.filter.LoggingFilter;
import com.shiraku.javacodespringsecurity.model.UserEntity;
import com.shiraku.javacodespringsecurity.service.OurUserDetailedService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    private final OurUserDetailedService ourUserDetailedService;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final LoggingFilter loggingFilter;

    public SecurityConfig(OurUserDetailedService ourUserDetailedService, JwtAuthenticationFilter jwtAuthenticationFilter, LoggingFilter loggingFilter) {
        this.ourUserDetailedService = ourUserDetailedService;
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
        this.loggingFilter = loggingFilter;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(authorizeRequests ->
                        authorizeRequests
                                .requestMatchers("/api/auth/login", "/api/auth/register", "/api/auth/home").permitAll()
                                .requestMatchers("/api/auth/admin/**").hasRole(UserEntity.Role.SUPER_ADMIN.name())
                                .requestMatchers("/api/auth/moderator/**").hasRole(UserEntity.Role.MODERATOR.name())
                                .requestMatchers("/api/auth/user/**").hasAnyRole(
                                        UserEntity.Role.USER.name(),
                                        UserEntity.Role.MODERATOR.name(),
                                        UserEntity.Role.SUPER_ADMIN.name())
                                .anyRequest().authenticated()
                )
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(loggingFilter, JwtAuthenticationFilter.class)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .headers(headers -> headers
                        .httpStrictTransportSecurity(hsts -> hsts.maxAgeInSeconds(31536000)
                                .includeSubDomains(true)
                        )
                );


        return httpSecurity.build();

    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(ourUserDetailedService);
        provider.setPasswordEncoder(passwordEncoder());
        return provider;
    }
}
