package com.motorny.jwtapp.config;

import com.motorny.jwtapp.security.jwt.AuthEntryPointJwt;
import com.motorny.jwtapp.security.jwt.JwtTokenFilter;
import com.motorny.jwtapp.security.jwt.JwtTokenProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class WebSecurityConfig {

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @Autowired
    private AuthEntryPointJwt unauthorizedHandler;


    private static final String ADMIN_ENDPOINT = "/api/v1/admin/**";
    private static final String LOGIN_ENDPOINT = "/api/v1/auth/login";

    @Autowired
    public WebSecurityConfig(JwtTokenProvider jwtTokenProvider) {
        this.jwtTokenProvider = jwtTokenProvider;
    }

   @Bean
   public JwtTokenFilter jwtTokenFilter() {
       return new JwtTokenFilter(jwtTokenProvider);
   }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfiguration) throws Exception {
        return authConfiguration.getAuthenticationManager();
    }

    @Bean

    public AuthenticationEntryPoint authenticationEntryPoint() {
        BasicAuthenticationEntryPoint entryPoint = new BasicAuthenticationEntryPoint();
        entryPoint.setRealmName("My Realm");
        return entryPoint;
    }

//    @Bean
//    public DaoAuthenticationProvider authenticationProvider() {
//        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
//
//        authProvider.setUserDetailsService(userDetailsService);
//        authProvider.setPasswordEncoder(passwordEncoder());
//
//        return authProvider;
//    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, AuthenticationEntryPoint unauthorizedHandler) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .exceptionHandling(exception -> exception.authenticationEntryPoint(unauthorizedHandler))
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(LOGIN_ENDPOINT).permitAll()
                        .requestMatchers(ADMIN_ENDPOINT).hasRole("ADMIN")
                        .anyRequest().authenticated())
                .addFilterBefore(jwtTokenFilter(), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
