CREATE DATABASE IF NOT EXISTS craftmapx;

USE craftmapx;

CREATE TABLE IF NOT EXISTS usuarios (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nome_completo VARCHAR(255) NOT NULL,
    nome_discord VARCHAR(255) NOT NULL,
    nome_aternos VARCHAR(255) NOT NULL,
    xbox_nick VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    senha VARCHAR(255) NOT NULL,
    data_aniversario DATE NOT NULL,
    data_cadastro TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX idx_email ON usuarios (email);