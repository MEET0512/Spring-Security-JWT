package com.patel.security.services;

import java.util.HashMap;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.patel.security.dto.JwtAuthenticationResponse;
import com.patel.security.dto.SignInRequest;
import com.patel.security.dto.SingUpRquest;
import com.patel.security.entity.Role;
import com.patel.security.entity.User;
import com.patel.security.repository.userRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

	private final userRepository userRepository;
	private final PasswordEncoder passwordEncoder;
	private final AuthenticationManager authenticationManager;
	private final JwtService jwtService;
	
	public User signUp(SingUpRquest singUpRquest) {
		User user = User.builder()
			.email(singUpRquest.getEmail())
			.firstName(singUpRquest.getFirstName())
			.lastName(singUpRquest.getLastName())
			.role(Role.USER)
			.password(passwordEncoder.encode(singUpRquest.getPassword()))
			.build();
		
		return userRepository.save(user);
	}
	
	public JwtAuthenticationResponse signIn(SignInRequest signInRequest) {
		System.out.println(signInRequest.getEmail());
		System.out.println(signInRequest.getPassword());
		try {
		authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(signInRequest.getEmail(), signInRequest.getPassword()));
		} catch(Exception e) {
			System.out.println(e.getMessage());
		}
		
			var user = userRepository.findByEmail(signInRequest.getEmail()).orElseThrow(() -> new IllegalArgumentException("Invalid email or password"));
			var token = jwtService.generatedToken(user);
			var refreshToken = jwtService.generateRefreshToken(new HashMap<>(), user);
			
			JwtAuthenticationResponse authenticationResponse = JwtAuthenticationResponse.builder()
																						.token(token)
																						.refreshToken(refreshToken)
																						.build();
			System.out.println("token" + authenticationResponse.getToken());
			return authenticationResponse;
		
	}
}
