package com.avania.Jwt;

import com.google.common.net.HttpHeaders;
import io.jsonwebtoken.security.Keys;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.crypto.SecretKey;

@ConfigurationProperties(prefix="application.jwt")
@Data
@NoArgsConstructor
public class JwtConfig {

    private String secretKey;
    private String tokenPrefix;
    private Integer tokenExpirationDate;



    public String getAuthorizationHeader(){
        return HttpHeaders.AUTHORIZATION;
    }
}
