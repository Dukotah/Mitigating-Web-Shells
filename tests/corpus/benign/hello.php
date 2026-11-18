<?php
$name = isset($_GET['name']) ? $_GET['name'] : 'world';
echo 'Hello, ' . htmlspecialchars($name, ENT_QUOTES, 'UTF-8') . '!';
