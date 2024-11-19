package com.example.trocarMensagens.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.security.core.userdetails.UserDetails;

import com.example.trocarMensagens.entity.User;





public interface UserRepository extends JpaRepository<User, String> {
    //UserDetails findByLogin(String nome);
	UserDetails findByNome(String nome);
	//Optional<User> findByNome(String nome);
}
