package com.patel.security.services;

import java.security.Key;
import java.util.Date;
import java.util.Map;
import java.util.function.Function;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {
	
	private String SECRET = "357638792F423F4428472B4B6250655368566D597133743677397A2443264629";
	
	@SuppressWarnings("deprecation")
	public String generatedToken(UserDetails userDetails) {
		System.out.println(userDetails.getUsername());
		return Jwts.builder().setSubject(userDetails.getUsername())
					.setIssuedAt(new Date(System.currentTimeMillis()))
					.setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))
					.signWith(getSigninKey(), SignatureAlgorithm.HS256)
					.compact();
	}
	
	@SuppressWarnings("deprecation")
	public String generateRefreshToken(Map<String, Object> extractClaim,UserDetails userDetails) {
		return Jwts.builder()
					.setClaims(extractClaim)
					.setSubject(userDetails.getUsername())
					.setIssuedAt(new Date(System.currentTimeMillis()))
					.setExpiration(new Date(System.currentTimeMillis() + 604861000))
					.signWith(getSigninKey(), SignatureAlgorithm.HS256)
					.compact();
	}
	
	public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

	private <T> T extractClaim(String token, Function<Claims, T> claimResolver) {
		final Claims claims = extractAllClaims(token);
		return claimResolver.apply(claims);
	}

	@SuppressWarnings("deprecation")
	private Claims extractAllClaims(String token) {
		return Jwts
				.parser()
                .setSigningKey(getSigninKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
	}

	private Key getSigninKey() {
		byte[] key = Decoders.BASE64.decode(SECRET);
		return Keys.hmacShaKeyFor(key);
	}

	public boolean validateToken(String token, UserDetails userDetails) {
		final String userName = extractUsername(token);
		return (userName.equals(userDetails.getUsername()) && !isTokenExpired(token));
	}

	private boolean isTokenExpired(String token) {
		return extractClaim(token, Claims::getExpiration).before(new Date());
	}
}
