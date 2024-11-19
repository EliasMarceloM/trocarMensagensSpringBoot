package com.example.trocarMensagens.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.example.trocarMensagens.repository.UserRepository;
@Service
public class AuthorizationService implements UserDetailsService {
	 @Autowired
	 UserRepository repository;
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		System.out.println("AuthorizationService ");
		
		 return repository.findByNome(username);
	}

}
