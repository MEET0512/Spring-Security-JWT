package com.patel.security.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.patel.security.entity.Role;
import com.patel.security.entity.User;

@Repository
public interface userRepository extends JpaRepository<User, Integer> {

	Optional<User> findByEmail(String email);
	
	User findByRole (Role role);
}
