package com.origincoding.authorization.config

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.provisioning.InMemoryUserDetailsManager

@Configuration
class AuthenticationConfig {
    @Bean
    fun userDetailsService(): UserDetailsService {
        return InMemoryUserDetailsManager(User("user", passwordEncoder().encode("password"), emptyList()))
    }

    @Bean fun passwordEncoder(): PasswordEncoder = BCryptPasswordEncoder()
}