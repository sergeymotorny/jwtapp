package com.motorny.jwtapp.repository;

import com.motorny.jwtapp.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepositoryI extends JpaRepository<Role, Long> {
    Role findByName(String name);
}
