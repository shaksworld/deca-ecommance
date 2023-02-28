package com.ecommance.decaecommance.util;


import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.ecommance.decaecommance.constants.SecurityConstant;
import com.ecommance.decaecommance.dto.response.TokenResponse;
import com.ecommance.decaecommance.model.User;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.stream.Collectors;

public class AppUtil {

    public static TokenResponse generateToken(Authentication authentication){
        User user = (User) authentication.getPrincipal();

        String userName = user.getName();

        Algorithm algorithm = Algorithm.HMAC256(SecurityConstant.SECRET.getBytes());
        String access_token = JWT.create()
                .withSubject(userName)
                .withExpiresAt(new java.util.Date(System.currentTimeMillis() + SecurityConstant.EXPIRATION_TIME))
                .withIssuedAt(new java.util.Date(System.currentTimeMillis()))
                .withClaim("role", authentication.getAuthorities()
                        .stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(Collectors.toList())
                )
                .sign(algorithm);
        return new TokenResponse(access_token);
    }

    public static String generateToken(User user){
        String userName = user.getName();

        Algorithm algorithm = Algorithm.HMAC256(SecurityConstant.SECRET.getBytes());
        String access_token = JWT.create()
                .withSubject(userName)
                .withExpiresAt(new java.util.Date(System.currentTimeMillis() + SecurityConstant.EXPIRATION_TIME))
                .withIssuedAt(new java.util.Date(System.currentTimeMillis()))
                .withClaim("role", user.getRole())
                .sign(algorithm);
        return access_token;
    }
}
