package com.ecommerce.userservice.configuration;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
public class ApplicationConfiguration {

    @Bean
    public BCryptPasswordEncoder getBycryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
