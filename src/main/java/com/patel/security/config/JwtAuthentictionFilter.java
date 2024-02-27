package com.patel.security.config;

import java.io.IOException;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.patel.security.services.JwtService;
import com.patel.security.services.userService;

import io.micrometer.common.util.StringUtils;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;

@Component
@AllArgsConstructor
public class JwtAuthentictionFilter extends OncePerRequestFilter {
	
	final JwtService jwtService;
	
	final userService Userservice;
	
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		String authHeader = request.getHeader("Authorization");
        String token = null;
        String userEmail = null;
        
        if(authHeader == null || !authHeader.startsWith("Bearer ")) {
        	filterChain.doFilter(request, response);
        	return;
        }
        
        token = authHeader.substring(7);
        userEmail = jwtService.extractUsername(token);
        
        if(StringUtils.isNotEmpty(userEmail) && SecurityContextHolder.getContext().getAuthentication() == null) {
        	UserDetails userDetails = Userservice.userDetailsService().loadUserByUsername(userEmail);
            if(jwtService.validateToken(token, userDetails)){
            	SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
            	
            	UsernamePasswordAuthenticationToken userToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
            	
            	userToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            	
            	securityContext.setAuthentication(userToken);
            	SecurityContextHolder.setContext(securityContext);
            	
            }
        }
        
        filterChain.doFilter(request, response);
	}

}
