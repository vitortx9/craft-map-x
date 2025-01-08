<?php
// Metodos de segurança
header("X-Frame-Options: DENY");
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
{   //Senha deve ter pelo menos 8 caracteres
    return strlen($password) >= 8;
}

// Verifica se o formulário foi enviado
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Verifica o token CSRF
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        die("Token CSRF inválido.");
    }

    // Captura e sanitiza os dados do formulário
    $email = sanitize_input($_POST['email']);
    $senha = sanitize_input($_POST['senha']);

    // Valida o E-Mail
    if (!validate_email($email)) {
        header("Location: login.php?error=invalid_email");
        exit();
    }
    // Valida a Senha
    if (!validate_password($senha)) {
        header("Location: login.php?error=weak_password");
        exit();
    }

    // Conexão com o banco de dados
    $conn = db_connect();

    // Prepara a consulta SQL para verificar o e-mail e a senha
    $sql = "SELECT id, senha FROM usuarios WHERE email = ?";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $stmt->store_result();

    if ($stmt->num_rows == 0) {
        // E-mail não encontrado, redireciona com mensagem de erro
        header("Location: login.php?error=email_not_found");
        exit();
    }

    $stmt->bind_result($id, $hashed_password);
    $stmt->fetch();
    $stmt->close();

    // Verifica a senha
    if (!password_verify($senha, $hashed_password)) {

        // Senha incorreta, redireciona com mensagem de erro
        header("Location: login.php?error=incorrect_password");
        exit();
    }

    // Inicia a sessão do usuário
    $_SESSION['user_id'] = $id;

    // Redireciona para a página de links
    header("Location: links.html");
    exit();
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
    <meta name="description" content="Seja Bem-Vindo de volta ao Craft Map X. Faça login para continuar sua jornada.">
    <meta name="keywords" content="servidor, minecraft, 1.21, gratis, Craft Map X, pe, pocket edition">
    <meta name="author" content="Vitor Alessandro Barboza da Silva">
    <link rel="icon" href="img/js.png" type="image/x-icon">
    <link rel="stylesheet" href="styles/cadastro.css">
    <title>CraftMapX | Login</title>
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
    <div class="container show" id="loginContainer">
        <!-- Mensagens de erro -->
        <?php
        if (isset($_GET['error'])) {
            $error_messages = [
                'invalid_email' => 'Formato de e-mail inválido.',
                'weak_password' => 'A senha deve ter pelo menos 8 caracteres.',
                'incorrect_password' => 'Senha incorreta.',
                'email_not_found' => 'E-mail não encontrado.',
            ];
            $error_code = $_GET['error'];
            if (array_key_exists($error_code, $error_messages)) {
                echo '<p class="error">' . $error_messages[$error_code] . '</p>';
            }
        }
        ?>
        <!-- Mensagens de erro -->

        <!--Formulário-->
        <form action="login.php" method="post">

            <!--Titulo-->
            <h1>Login</h1>
            <!--Titulo-->

            <!--E-mail-->
                <label for="email">E-mail:</label>
                <input type="email" id="email" name="email" placeholder="ex. lonely@secret.com" required>
            <!--E-mail-->

            <!--Senha-->
                <label for="senha">Senha:</label>
                <input type="password" id="senha" name="senha" placeholder="ex. vitor123" required>
            <!--Senha-->

            <!-- Adiciona o token CSRF ao formulário -->
            <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">

            <!--Botão de cadastra-->
            <input type="submit" value="Entrar">
            <!--Botão de cadastra-->

            <!--Ainda não tem conta?-->
            <p>Ainda não tem conta? <a href="cadastro.php">Cadastre-se</a></p>
            <!--Ainda não tem conta?-->

        </form>
        <!--Formulário-->

    </div>
    <!--Conteiner-->


    <!--Rodapé-->
    <footer>
        <p>&copy; 2024 Primeiro Site de <a href="https://www.instagram.com/vitor_4lessan?igshid=MzRlODBiNWFlZA=="
                target="_blank">@vitor_4lessan</a></p>
    </footer>
    <!--Rodapé-->

    <script nonce="<?php echo $nonce; ?>" src="scripts/main.js"></script>
    
</body>
<!--corpo-->

</html>