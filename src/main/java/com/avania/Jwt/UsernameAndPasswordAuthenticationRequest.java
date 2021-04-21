package com.avania.Jwt;

import lombok.Data;

@Data
public class UsernameAndPasswordAuthenticationRequest {
    private String username;
    private String password;

    public UsernameAndPasswordAuthenticationRequest() {
    }
}
