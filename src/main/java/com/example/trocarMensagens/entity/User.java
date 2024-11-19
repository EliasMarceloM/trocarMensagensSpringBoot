package com.example.trocarMensagens.entity;

import java.util.Collection;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;


import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Table(name = "users")
@Entity(name = "users")
public class User implements UserDetails {
	 	@Id
	    @GeneratedValue(strategy = GenerationType.UUID)
	    private String id;
	    private String nome;
	    private String password;
	    private UserRole role;
	    
	    // Construtor padrão
	    public User() {
	    }
	    
	    public User(String login, String password, UserRole role){
	        this.nome = login;
	        this.password = password;
	        this.role = role;
	    }
	    
	    
	    
		@Override
		public Collection<? extends GrantedAuthority> getAuthorities() {
	        if(this.role == UserRole.ADMIN) return List.of(new SimpleGrantedAuthority("ROLE_ADMIN"), new SimpleGrantedAuthority("ROLE_USER"));
	        else return List.of(new SimpleGrantedAuthority("ROLE_USER"));
			
		}
		@Override
		public String getPassword() {
			// TODO Auto-generated method stub
			return  this.password;
		}
		@Override
		public String getUsername() {
			// TODO Auto-generated method stub
			return this.nome;
		}
		
	    public String  getId() {
	        return this.id;
	    }

		public String getNome() {
			return nome;
		}

		public void setNome(String nome) {
			this.nome = nome;
		}

		public UserRole getRole() {
			return role;
		}

		public void setRole(UserRole role) {
			this.role = role;
		}

		public void setId(String id) {
			this.id = id;
		}

		public void setPassword(String password) {
			this.password = password;
		}
}
