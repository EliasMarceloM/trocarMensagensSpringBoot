package com.example.trocarMensagens.security;




import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.example.trocarMensagens.repository.UserRepository;

import java.io.IOException;
import java.util.Arrays;

@Component
public class SecurityFilter extends OncePerRequestFilter {

    @Autowired
    private TokenService tokenService;

    @Autowired
    private UserRepository userRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) 
            throws ServletException, IOException {

       
    	String token ="";
        System.out.println("token1"+token); 
        // Caso o token não esteja no header, tenta recuperar dos cookies
        if (token == null || token == "") {
            token = readCookie("tokenAuth", request);
        }
        System.out.println("token2"+token); 
        if (token !="" || token != null) {
            try {
                // Valida o token e recupera o login do usuário
                String username = tokenService.validateToken(token);

                if (username != null) {
                    // Carrega os detalhes do usuário no banco de dados
                    UserDetails user = userRepository.findByNome(username);

                    if (user != null) {
                        // Autentica o usuário no contexto de segurança
                    	System.out.println("Autentica o usuário no contexto de segurança");
                        var authentication = new UsernamePasswordAuthenticationToken(
                                user, null, user.getAuthorities());
                        SecurityContextHolder.getContext().setAuthentication(authentication);
                    } else {
                        System.out.println("Usuário não encontrado para o token.");
                    }
                }
            } catch (Exception e) {
                System.out.println("Erro ao processar o token: " + e.getMessage());
            }
        } else {
            System.out.println("Nenhum token encontrado na requisição.");
        }

        // Continua o processamento da requisição
        filterChain.doFilter(request, response);
    }

    
    /**
     * Lê o valor de um cookie específico pelo nome.
     */
    private String readCookie(String key, HttpServletRequest request) {
        try {
            return Arrays.stream(request.getCookies())
                    .filter(c -> key.equals(c.getName()))
                    .map(Cookie::getValue)
                    .findAny()
                    .orElse(null); // Retorna null se o cookie não for encontrado
        } catch (Exception e) {
            System.out.println("Erro ao ler o cookie: " + e.getMessage());
            return null;
        }
    }
}
