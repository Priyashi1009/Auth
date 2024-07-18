package com.auth.authproject.service;


import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.auth.authproject.model.UserLogin;
import com.auth.authproject.repository.UserLoginRepository;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.*;
import java.nio.charset.StandardCharsets;

@Service
public class UserLoginService {

    @Autowired
    private UserLoginRepository userRepository;

    private static final long TOKEN_VALIDITY = 60000; 

    private static final String SECRET = "zyxabczyxabczyxabczyxabczyxabczyxabczyxabczyxabc";

    public String generateJwtToken(String username, String password) {
        boolean isValid = validateUser(username, password);

        if (isValid) {
            Instant now = Instant.now();
            SecretKey key = Keys.hmacShaKeyFor(SECRET.getBytes(StandardCharsets.UTF_8));
            Optional<UserLogin> userOptional = userRepository.findByUsername(username);
            if (userOptional.isPresent()) {
                UserLogin user = userOptional.get();
                String role = user.getRole();

            return Jwts.builder()
                    .setSubject(username)
                    .claim("role", role) 
                    .setIssuedAt(Date.from(now))
                    .setExpiration(Date.from(now.plusMillis(TOKEN_VALIDITY)))
                    .signWith(key, SignatureAlgorithm.HS256)
                    .compact();
            }
        }
        return null;
    }

    private boolean validateUser(String username, String password) {
        Optional<UserLogin> userOptional = userRepository.findByUsername(username);

        if (userOptional.isPresent()) {
            UserLogin user = userOptional.get();
            return user.getPassword().equals(password);
        }
        return false;
    }

    public Map<String, String> loginService(String username, String password) {
        String token = generateJwtToken(username, password);
        Map<String, String> response = new HashMap<>();
        if (token != null) {
            response.put("token", token);
        } else {
            response.put("error", "Invalid username or password");
        }
        return response;
    }
    
    public Map<String, Object> validateJwtToken(String token) {

        Map<String, Object> response = new HashMap<>();
        try {
            SecretKey key = Keys.hmacShaKeyFor(SECRET.getBytes(StandardCharsets.UTF_8));
            var claims = Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();

            String role = claims.get("role", String.class); // Extracting the role from claims

            response.put("role", role);
            response.put("Status"," Application is running succesfully");

        } catch (Exception e) {
        	response.put("error occured", "Token mismatch/Logged out");
        }
        return response;
    }
}