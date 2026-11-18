<?php
require_once __DIR__ . '/config.php';

function clean_field($value)
{
    return trim(strip_tags((string) $value));
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = filter_input(INPUT_POST, 'email', FILTER_VALIDATE_EMAIL);
    $message = clean_field(filter_input(INPUT_POST, 'message'));
    if ($email && $message !== '') {
        $stmt = $pdo->prepare('INSERT INTO messages (email, body) VALUES (?, ?)');
        $stmt->execute([$email, $message]);
        header('Location: /thanks.html');
        exit;
    }
}
?>
<form method="post" action="/contact.php">
  <input type="email" name="email" required>
  <textarea name="message"></textarea>
  <button type="submit">Send</button>
</form>
