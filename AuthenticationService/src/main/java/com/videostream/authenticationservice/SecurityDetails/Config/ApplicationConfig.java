package com.videostream.authenticationservice.SecurityDetails.Config;

import com.videostream.authenticationservice.SecurityDetails.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class ApplicationConfig {
    private final UserRepository repository;
    @Autowired
    public ApplicationConfig(UserRepository repository){
        this.repository = repository;
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new Argon2PasswordEncoder(16,32,1,19923,2);
    }

}
