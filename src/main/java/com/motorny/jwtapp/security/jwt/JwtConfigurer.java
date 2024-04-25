package com.motorny.jwtapp.security.jwt;

import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

public class JwtConfigurer extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {
    private JwtTokenProvider jwtTokenProvider;

    public JwtConfigurer(JwtTokenProvider jwtTokenProvider) {
        this.jwtTokenProvider = jwtTokenProvider;
    }

    // Каждый запрос, перед тем как быть переданным серверу, он должен пройти
    // через проверку JwtTokenFilter (20 строчка)
    // JwtTokenFilter анализирует наш запрос (смотрит, что есть токен и токен
    // валидный) мы продолжаем работать с ним.

    @Override
    public void configure(HttpSecurity httpSecurity) {
        JwtTokenFilter jwtTokenFilter = new JwtTokenFilter(jwtTokenProvider);
        // Такая же строчка в WebSecurityConfig
        httpSecurity.addFilterBefore(jwtTokenFilter, UsernamePasswordAuthenticationFilter.class);
    }
}
