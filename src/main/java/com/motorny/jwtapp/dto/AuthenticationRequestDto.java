package com.motorny.jwtapp.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class AuthenticationRequestDto {
    @NotBlank
    private String username;
    @NotBlank
    private String password;
}
