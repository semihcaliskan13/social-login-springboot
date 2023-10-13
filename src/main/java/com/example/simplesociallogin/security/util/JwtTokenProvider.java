package com.example.simplesociallogin.security.util;


import com.example.simplesociallogin.security.CustomUserDetails;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.sql.Date;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

@Slf4j
@Component
public class JwtTokenProvider {

    @Value("${app.jwt.secret}")
    private String secretKey;

    @Value("${app.jwt.expiration.minutes}")
    private Long expiration;

    public static final String TOKEN_TYPE = "JWT";
    public static final String TOKEN_ISSUER = "social-login";
    public static final String TOKEN_AUDIENCE = "social-login-app";

    public String generateJwtToken(Authentication authentication){
        CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();

        List<String> roles = userDetails.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .toList();

        byte[] signinKey = secretKey.getBytes();

        return Jwts.builder()
                .setHeaderParam("type", TOKEN_TYPE)
                .signWith(Keys.hmacShaKeyFor(signinKey), SignatureAlgorithm.HS256)
                .setExpiration(Date.from(ZonedDateTime.now().plusMinutes(expiration).toInstant()))
                .setIssuedAt(Date.from(ZonedDateTime.now().toInstant()))
                .setId(UUID.randomUUID().toString())
                .setIssuer(TOKEN_ISSUER)
                .setAudience(TOKEN_AUDIENCE)
                .setSubject(userDetails.getUsername())
                .claim("role", roles)
                .claim("name", userDetails.getName())
                .claim("email", userDetails.getEmail())
                .claim("preferred_username", userDetails.getUsername())
                .compact();
    }

    public Optional<Jws<Claims>> validateTokenAndGetJws(String token){
        try {
            byte[] signingKey = secretKey.getBytes();

            Jws<Claims> jws = Jwts.parserBuilder()
                    .setSigningKey(signingKey)
                    .build()
                    .parseClaimsJws(token);

            return Optional.of(jws);
        } catch (ExpiredJwtException exception) {
            log.error("Request to parse expired JWT : {} failed : {}", token, exception.getMessage());
        } catch (UnsupportedJwtException exception) {
            log.error("Request to parse unsupported JWT : {} failed : {}", token, exception.getMessage());
        } catch (MalformedJwtException exception) {
            log.error("Request to parse invalid JWT : {} failed : {}", token, exception.getMessage());
        } catch (SignatureException exception) {
            log.error("Request to parse JWT with invalid signature : {} failed : {}", token, exception.getMessage());
        } catch (IllegalArgumentException exception) {
            log.error("Request to parse empty or null JWT : {} failed : {}", token, exception.getMessage());
        }
        return Optional.empty();

    }
}
