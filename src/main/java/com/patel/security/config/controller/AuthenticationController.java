package com.patel.security.config.controller;

import java.util.Optional;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.patel.security.dto.JwtAuthenticationResponse;
import com.patel.security.dto.SignInRequest;
import com.patel.security.dto.SingUpRquest;
import com.patel.security.entity.User;
import com.patel.security.repository.userRepository;
import com.patel.security.services.AuthenticationService;

import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {

	private final AuthenticationService authenticationService;
	private final userRepository repository;
	
	@PostMapping("/signup")
	public ResponseEntity<User> signup(@RequestBody SingUpRquest singUpRquest){
		return ResponseEntity.ok(authenticationService.signUp(singUpRquest));
	}
	
	@PostMapping("/signin")
	public ResponseEntity<JwtAuthenticationResponse> signIn(@RequestBody SignInRequest signInRquest){
		return ResponseEntity.ok(authenticationService.signIn(signInRquest));
	}
	
	@GetMapping
	public ResponseEntity<String> home(){
		return ResponseEntity.ok("Home Page.");
	}
}
