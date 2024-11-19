package com.example.trocarMensagens.security;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.example.trocarMensagens.entity.User;




@Service
public class TokenService {

    @Value("${api.security.token.secret}")
    private String secret;

    /**
     * Gera um token JWT para o usuário fornecido.
     *
     * @param user Usuário para o qual o token será gerado
     * @return Token JWT gerado
     */
    public String generateToken(User user) {
        try {
            Algorithm algorithm = Algorithm.HMAC256(secret);
            return JWT.create()
                    .withIssuer("auth-api") // Identifica quem gerou o token
                    .withSubject(user.getUsername()) // Identifica o usuário
                    .withExpiresAt(generateExpirationDate()) // Define a validade do token
                    .sign(algorithm); // Assina o token
        } catch (JWTCreationException exception) {
            throw new RuntimeException("Erro ao gerar o token JWT", exception);
        }
    }

    /**
     * Valida o token JWT e retorna o username contido no payload.
     *
     * @param token Token JWT a ser validado
     * @return Username contido no token, ou null se inválido
     */
    public String validateToken(String token) {
        try {
            Algorithm algorithm = Algorithm.HMAC256(secret);
            return JWT.require(algorithm)
                    .withIssuer("auth-api") // Valida o emissor do token
                    .build()
                    .verify(token) // Verifica a assinatura e decodifica o token
                    .getSubject(); // Retorna o username do payload
        } catch (JWTVerificationException exception) {
            System.out.println("Erro ao validar o token: " + exception.getMessage());
            return null; // Retorna null em caso de token inválido
        }
    }

    /**
     * Gera a data de expiração do token (2 horas a partir do momento atual).
     *
     * @return Instante da expiração do token
     */
    private Instant generateExpirationDate() {
        return LocalDateTime.now()
                .plusHours(2) // Define a validade de 2 horas
                .toInstant(ZoneOffset.of("-03:00")); // Considera o fuso horário UTC-3
    }
}
