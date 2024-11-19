package com.example.trocarMensagens.entity;

import java.util.List;

public record MessageDTO(List<Message> oldMessages, String newMessageContent) {

}
