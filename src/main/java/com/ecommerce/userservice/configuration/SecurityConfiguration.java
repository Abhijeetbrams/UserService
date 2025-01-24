package com.ecommerce.userservice.configuration;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;


@Configuration
@EnableWebSecurity // By adding @EnableWebSecurity, Spring Security's filters are added to the Spring
// application context. These filters intercept incoming HTTP requests to apply security measures
// like authentication and authorization.

public class SecurityConfiguration {
//
//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//        http
//                .authorizeHttpRequests(auth -> auth
//                        .requestMatchers("/users/signup").permitAll() // Allow public access to signup
//                        .requestMatchers("/users/login").permitAll()  // Allow public access to login
//                        .requestMatchers("/users/logout").permitAll() // Allow public access to logout
//                        .requestMatchers("/users/validate").permitAll()
//                        .anyRequest().authenticated()                // Secure other endpoints
//                )
//                .csrf(csrf -> csrf.disable())
//                // Disable - For REST APIs or token-based authentication where CSRF is irrelevant.
//                // Enable - For traditional web applications using session-based authentication (e.g., form-based login).
//                .httpBasic(Customizer.withDefaults()); // Use HTTP Basic Authentication
//
//
//        return http.build();
//    }
}
