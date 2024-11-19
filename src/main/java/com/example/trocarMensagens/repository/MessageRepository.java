package com.example.trocarMensagens.repository;

import com.example.trocarMensagens.entity.Message;
import com.example.trocarMensagens.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface MessageRepository extends JpaRepository<Message, UUID> {

    // Encontrar todas as mensagens de um usuário específico (pelo autor)
    List<Message> findByAuthor(User author);

    // Encontrar todas as mensagens de um conjunto de usuários (ex. feed)
    List<Message> findByAuthorIn(List<User> authors);

    // Encontrar as mensagens mais recentes (ordenadas pela data de criação)
    List<Message> findTop10ByOrderByTimestampDesc();
}
