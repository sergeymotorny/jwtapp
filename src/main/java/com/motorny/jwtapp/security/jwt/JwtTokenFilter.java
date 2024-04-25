package com.motorny.jwtapp.security.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.GenericFilterBean;

import java.io.IOException;

public class JwtTokenFilter extends GenericFilterBean {

    // Класс, который фильтрует запросы на наличие токена

    private JwtTokenProvider jwtTokenProvider;

    public JwtTokenFilter(JwtTokenProvider jwtTokenProvider) {
        this.jwtTokenProvider = jwtTokenProvider;
    }

    // Суть метода: каждый запрос который приходит ко мне на сервер - валидирую
    // есть токен - будет часть
    // нет токена - не будет аутентификации

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain)
            throws IOException, ServletException {
        // Получаем токен из запроса (из ServletRequest)
        String token = jwtTokenProvider.resolveToken((HttpServletRequest) request);
        // Если токен != null and jwtTokenProvider валидный
        if (token != null && jwtTokenProvider.validateToken(token)) {
            // передаем аутентификацию
            Authentication authentication = jwtTokenProvider.getAuthentication(token);
            // если аутентификация != null
            if (authentication != null) {
                ((UsernamePasswordAuthenticationToken)authentication)
                        .setDetails(new WebAuthenticationDetailsSource()
                                .buildDetails((HttpServletRequest) request));
                // аутентифицируем запрос
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }
        filterChain.doFilter(request, response);
    }
}
