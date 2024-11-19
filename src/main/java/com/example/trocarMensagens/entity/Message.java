package com.example.trocarMensagens.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "messages")
public class Message {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private UUID id;  // ID único da mensagem, usando UUID para garantir um identificador único global

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "author_id", nullable = false)
    private User author;  // O usuário que postou a mensagem (autor)

    @Column(nullable = false, length = 1000)
    private String content;  // O conteúdo da mensagem (texto do post)

    @Column(nullable = false)
    private LocalDateTime timestamp;  // Data e hora de postagem

    // Construtor padrão
    public Message() {
    }

    // Construtor com parâmetros
    public Message(User author, String content) {
        this.author = author;
        this.content = content;
        this.timestamp = LocalDateTime.now();  // Armazena o momento da postagem
    }

    // Getters e Setters
    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public User getAuthor() {
        return author;
    }

    public void setAuthor(User author) {
        this.author = author;
    }

    public String getContent() {
        return content;
    }

    public void setContent(String content) {
        this.content = content;
    }

    public LocalDateTime getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(LocalDateTime timestamp) {
        this.timestamp = timestamp;
    }
}
