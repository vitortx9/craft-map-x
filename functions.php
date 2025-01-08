<?php
// functions.php

// Erro ao cadastrar, redireciona com mensagem de erro
function redirect_with_error($location, $error)
{
    header("Location: $location?error=" . urlencode($error));
    exit();
}
// Gera um token CSRF para o formulário
function generate_csrf_token()
{
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
}
// Verifica o token CSRF
function validate_csrf_token($token)
{
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}
?>