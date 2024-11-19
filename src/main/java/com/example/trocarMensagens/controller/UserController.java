package com.example.trocarMensagens.controller;

import com.example.trocarMensagens.entity.Message;
import com.example.trocarMensagens.entity.MessageDTO;
import com.example.trocarMensagens.entity.User;
import com.example.trocarMensagens.repository.UserRepository;
import com.example.trocarMensagens.security.SecurityConfigurations;
import com.example.trocarMensagens.security.TokenService;
import com.example.trocarMensagens.service.MessageService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.util.Arrays;
import java.util.List;

@Controller
public class UserController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private TokenService tokenService;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private MessageService messageService;
    
    @Autowired
    private PasswordEncoder passwordEncoder;

    // Página de registro
    @GetMapping("/registrar")
    public ModelAndView showRegistrationPage() {
        return new ModelAndView("registro", "user", new User());
    }

    // Processa o formulário de registro
    @PostMapping("/registrar")
    public ModelAndView registerUser(User user, HttpServletResponse response) {
        ModelAndView mv = new ModelAndView("registro");

        if (userRepository.findByNome(user.getUsername()) != null) {
            mv.addObject("error", "Usuário já existe.");
        } else {
           // user.setPassword(user.getPassword());  // Codificando a senha
        	user.setPassword(passwordEncoder.encode(user.getPassword()));
        	userRepository.save(user);
            generateTokenAndSetCookies(user, response);
            mv.setViewName("redirect:/feed");  // Redireciona para o feed após registro
        }

        return mv;
    }

    // Página de login
    @GetMapping("/logar")
    public ModelAndView showLoginPage() {
        return new ModelAndView("login", "user", new User());
    }

    // Processa o login
    @PostMapping("/logado")
    public ModelAndView loginUser(User user, HttpServletResponse response) {
        ModelAndView mv = new ModelAndView("feed");

        var authToken = new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());
        var auth = authenticationManager.authenticate(authToken);
        generateTokenAndSetCookies((User) auth.getPrincipal(), response);

        mv.setViewName("redirect:/feed");  // Redireciona para o feed após login

        return mv;
    }

    
 // Exibir as mensagens do feed
    @GetMapping("/feed")
    public ModelAndView showFeed(HttpServletRequest request) {
        String tokenNome = readCookie("tokenNome", request);

        if (tokenNome != null) {
            List<Message> allMessages = messageService.getLatestMessages();  // Pega as últimas mensagens
            ModelAndView mv = new ModelAndView("feed");
            
            // Passa para o frontend as mensagens antigas e o campo de nova mensagem
            mv.addObject("objeto", new MessageDTO(allMessages, null));  // null, pois não há nova mensagem inicialmente
            return mv;
        } else {
            return new ModelAndView("redirect:/logar");  // Redireciona para a página de login caso o token seja inválido
        }
    }

    // Processa a postagem de novas mensagens
    @PostMapping("/feedSalve")
    public ModelAndView saveFeedMessage(@RequestParam String content, HttpServletRequest request) {
        String tokenNome = readCookie("tokenNome", request);

        if (tokenNome != null && content != null && !content.trim().isEmpty()) {
            User user = (User) userRepository.findByNome(tokenNome);  // Busca o usuário pelo nome
            if (user != null) {
                messageService.postMessage(user, content);  // Salva a nova mensagem
            }
        }

        return new ModelAndView("redirect:/feed");  // Redireciona para o feed após salvar a mensagem
    }

    // Função que envia o cookie
    private void generateTokenAndSetCookies(User user, HttpServletResponse response) {
        try {
            String token = tokenService.generateToken(user);
            String username = user.getUsername();
            enviarCookie(response, "tokenAuth", token);
            enviarCookie(response, "tokenNome", username);
        } catch (Exception e) {
            System.out.println("Erro ao gerar o token: " + e.getMessage());
        }
    }

    // Função que envia o cookie
    private void enviarCookie(HttpServletResponse response, String nomeCookie, String valorCookie) {
        Cookie cookie = new Cookie(nomeCookie, valorCookie);
        cookie.setMaxAge(60 * 60);  // 1 hora
        cookie.setPath("/");  // O cookie será acessível para toda a aplicação
        response.addCookie(cookie);
    }

    // Função que lê um cookie
    private String readCookie(String key, HttpServletRequest request) {
        try {
            return Arrays.stream(request.getCookies())
                    .filter(c -> key.equals(c.getName()))
                    .map(Cookie::getValue)
                    .findAny()
                    .orElse(null);  // Retorna null se o cookie não for encontrado
        } catch (Exception e) {
            System.out.println("Erro ao ler cookie: " + e.getMessage());
            return null;
        }
    }
}
