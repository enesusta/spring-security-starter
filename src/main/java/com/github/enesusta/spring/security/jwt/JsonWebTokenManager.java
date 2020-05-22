package com.github.enesusta.spring.security.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

public class JsonWebTokenManager {

    private final String SECRET_KEY;
    private final int VALIDITY;

    public JsonWebTokenManager(final String SECRET_KEY,
                               final int VALIDITY) {
        this.SECRET_KEY = SECRET_KEY;
        this.VALIDITY = VALIDITY;
    }

    public final String extractUsername(final String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public final Date extractExpiration(final String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public <T> T extractClaim(final String token, final Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(final String token) {
        return Jwts.parser().setSigningKey(SECRET_KEY).parseClaimsJws(token).getBody();
    }

    private Boolean isTokenExpired(final String token) {
        return extractExpiration(token).before(new Date());
    }

    public final String generateToken(final String username) {
        Map<String, Object> claims = new HashMap<>();
        return createToken(claims, username);
    }

    private String createToken(final Map<String, Object> claims, final String subject) {

        return Jwts.builder().setClaims(claims).setSubject(subject).setIssuedAt(new Date(System.currentTimeMillis()))
            .setExpiration(new Date(System.currentTimeMillis() + VALIDITY))
            .signWith(SignatureAlgorithm.HS256, SECRET_KEY).compact();
    }

    public final Boolean validateToken(final String token, final UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

}
