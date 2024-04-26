package com.motorny.jwtapp.repository;

import com.motorny.jwtapp.model.User;
import org.springframework.data.jpa.repository.JpaRepository;


public interface UserRepositoryI extends JpaRepository<User, Long> {
    User findByUsername(String name);
}
