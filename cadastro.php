<?php
// Metodos de segurança
header("X-Content-Type-Options: nosniff");
header("X-XSS-Protection: 1; mode=block");
header("Strict-Transport-Security: max-age=31536000; includeSubDomains; preload");
header("Referrer-Policy: no-referrer-when-downgrade");
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-random'; style-src 'self'; img-src 'self' data:;");

// Inicia a sessão
session_start();

// Inclui o arquivo de conexão e funções
include 'db_connect.php';
include 'functions.php';

// Função para sanitizar os dados de entrada
function sanitize_input($data)
{
    return htmlspecialchars(trim($data));
}

// Função para validar o formato do e-mail
function validate_email($email)
{
    return filter_var($email, FILTER_VALIDATE_EMAIL);
}

// Função para validar a senha
function validate_password($password)
{   // Senha deve ter pelo menos 8 caracteres
    return strlen($password) >= 8;
}

// Verifica se o formulário foi enviado
if ($_SERVER["REQUEST_METHOD"] == "POST") {

    // Verifica o token CSRF
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        die("Token CSRF inválido.");
    }

    // Captura e sanitiza os dados do formulário
    $nome_completo = sanitize_input($_POST['nome_completo']);
    $nome_aternos = sanitize_input($_POST['nome_aternos']);
    $nome_discord = sanitize_input($_POST['nome_discord']);
    $xbox_nick = sanitize_input($_POST['xbox_nick']);
    $email = sanitize_input($_POST['email']);
    $senha = sanitize_input($_POST['senha']);
    $confirmar_senha = sanitize_input($_POST['confirmar_senha']);
    $data_aniversario = sanitize_input($_POST['data_aniversario']);


    // Valida o E-Mail
    if (!validate_email($email)) {
        header("Location: cadastro.php?error=invalid_email");
        exit();
    }
    // Valida a Senha
    if (!validate_password($senha)) {
        header("Location: cadastro.php?error=weak_password");
        exit();
    }

    // Verifica se as senhas são as mesmas
    if ($senha !== $confirmar_senha) {
        header("Location: cadastro.php?error=password_mismatch");
        exit();
    }

    // Conexão com o banco de dados
    $conn = db_connect();

    // Prepara a consulta SQL para verificar se o e-mail já está registrado
    $sql = "SELECT id FROM usuarios WHERE email = ?";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $stmt->store_result();

    if ($stmt->num_rows > 0) {
        // E-mail já registrado, redireciona com mensagem de erro
        header("Location: cadastro.php?error=email_registered");
        exit();
    }

    $stmt->close();

    // Criptografa a senha
    $hashed_password = password_hash($senha, PASSWORD_BCRYPT);

    // Prepara a consulta SQL para inserir o novo usuário
    $sql = "INSERT INTO usuarios (nome_completo, email, nome_aternos, nome_discord, senha, xbox_nick, data_aniversario) VALUES (?, ?, ?, ?, ?, ?,?)";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("sssssss", $nome_completo, $email, $nome_aternos, $nome_discord, $hashed_password, $xbox_nick, $data_aniversario);

    if ($stmt->execute()) {
        // Cadastro bem-sucedido, redireciona para a página de login
        header("Location: links.html");
        exit();
    } else {
        // Erro ao cadastrar, redireciona com mensagem de erro
        header("Location: cadastro.php?error=registration_failed");
        exit();
    }

    $stmt->close();
    $conn->close();
}

// Gera um token CSRF para o formulário
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Gerar nonce para CSP
$nonce = bin2hex(random_bytes(16));
?>

<!DOCTYPE html>
<html lang="pt-br">

<!--Cabeçario-->
<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' 'nonce-<?php echo $nonce; ?>'; style-src 'self'; img-src 'self' data:;">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="description" content="Seja Bem-Vindo a Craft Map X, mal podemos esperar para conhecer você.">
    <meta name="keywords" content="servidor, minecraft, 1.21, gratis, Craft Map X, pe, pocket edition">
    <meta name="author" content="Vitor Alessandro Barboza da Silva">
    <link rel="icon" href="img/js.png" type="image/x-icon">
    <link rel="stylesheet" href="styles/cadastro.css">
    <title>CraftMapX | Cadastro</title>
</head>
<!--Cabeçario-->

<!--Corpo-->
<body>

    <!--Cabeça-->
    <header>
        <img src="img/craftmapx.png" alt="logo da craft map x" width="450" height="70">
    </header>
    <!--Cabeça-->


    <!--Container-->
    <div class="container show" id="cadastroContainer">

        <!-- Mensagens de erro -->
        <?php
        if (isset($_GET['error'])) {
            $error_messages = [
                'invalid_email' => 'Formato de e-mail inválido.',
                'weak_password' => 'A senha deve ter pelo menos 8 caracteres.',
                'password_mismatch' => 'As senhas não coincidem.',
                'email_registered' => 'Este e-mail já está registrado.',
                'registration_failed' => 'Falha ao registrar. Tente novamente.'
            ];
            $error_code = $_GET['error'];
            if (array_key_exists($error_code, $error_messages)) {
                echo '<p class="error">' . $error_messages[$error_code] . '</p>';
            }
        }
        ?>
        <!-- Mensagens de erro -->

        <!--Formulário-->
        <form action="cadastro.php" method="post">

            <!--Titulo-->
            <h1>Cadastro</h1>
            <!--Titulo-->

            <!--Seu Nome-->
                <label for="nome_completo">Seu Nome:</label>
                <input type="text" id="nome_completo" name="nome_completo" placeholder="ex. vitor Alessandro" required>
            <!--Seu Nome-->

            <!--Nome de Usuário do Aternos-->
                <label for="nome_aternos">Nome de Usuário do Aternos:</label>
                <input type="text" id="nome_aternos" name="nome_aternos" placeholder="ex. Vitortx9" required>
            <!--Nome de Usuário do Aternos-->

            <!--Nome de Usuário do Discord-->
                <label for="nome_discord">Nome de Usuário do Discord:</label>
                <input type="text" id="nome_discord" name="nome_discord" placeholder="ex. vitor_4lessan" required>
            <!--Nome de Usuário do Discord-->

            <!--Nick de Usuário do Xbox-->
                <label for="xbox_nick">Gamertag do Xbox:</label>
                <input type="text" id="xbox_nick" name="xbox_nick" placeholder="ex. VITOR #7857" required>
            <!--Nick de Usuário do Xbox-->

            <!--E-mail-->
                <label for="email">E-mail:</label>
                <input type="email" id="email" name="email" placeholder="ex. lonely@secret.com" required>
            <!--E-mail-->

            <!--Senha-->
                <label for="senha">Senha:</label>
                <input type="password" id="senha" name="senha" placeholder="ex. vitor123" required>
            <!--Senha-->

            <!--Confirmar Senha-->
                <label for="confirmar_senha">Confirmar Senha:</label>
                <input type="password" id="confirmar_senha" name="confirmar_senha" placeholder="ex. vitor123" required>
            <!--Confirmar Senha-->

            <!--Data de Nascimento-->
                <label for="data_aniversario">Data de Nascimento</label>
                <input id="data_aniversario" name="data_aniversario" required="required" type="date" />
            <!--Data de Nascimento-->

            <!--Adiciona o token CSRF ao formulário-->
            <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">

            <!--Botão de cadastra-->
            <input type="submit" value="Cadastrar">
            <!--Botão de cadastra-->

            <!--Já tem conta?-->
            <p>Já tem conta? <a href="login.php">Faça login</a></p>
            <!--Já tem conta?-->

        </form>
        <!--Formulário-->

    </div>
    <!--Conteiner-->


    <!--Rodapé-->
    <footer>
        <p>&copy; 2024 Primeiro Site de <a href="https://www.instagram.com/vitor_4lessan?igshid=MzRlODBiNWFlZA==" target="_blank">@vitor_4lessan</a></p>
    </footer>
    <!--Rodapé-->

    <script nonce="<?php echo $nonce; ?>" src="scripts/main.js"></script>

</body>
<!--Corpo-->

</html>