package com.example.trocarMensagens.service;

import com.example.trocarMensagens.entity.Message;
import com.example.trocarMensagens.entity.User;
import com.example.trocarMensagens.repository.MessageRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.UUID;

@Service
public class MessageService {

    @Autowired
    private MessageRepository messageRepository;

    // Salvar uma nova mensagem
    public Message postMessage(User author, String content) {
        Message message = new Message(author, content);
        return messageRepository.save(message);
    }

    // Buscar mensagens de um autor específico
    public List<Message> getMessagesByUser(User user) {
        return messageRepository.findByAuthor(user);
    }

    // Buscar o feed de mensagens dos usuários seguidos
    public List<Message> getFeedMessages(List<User> followedUsers) {
        return messageRepository.findByAuthorIn(followedUsers);
    }

    // Buscar as últimas 10 mensagens (feed geral)
    public List<Message> getLatestMessages() {
        return messageRepository.findTop10ByOrderByTimestampDesc();
    }

    // Buscar uma mensagem específica pelo ID (UUID)
    public Message getMessageById(UUID messageId) {
        return messageRepository.findById(messageId).orElse(null);
    }

    // Excluir uma mensagem (por ID)
    public boolean deleteMessage(UUID messageId) {
        if (messageRepository.existsById(messageId)) {
            messageRepository.deleteById(messageId);
            return true;
        }
        return false;
    }
}
