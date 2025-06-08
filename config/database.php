<?php
// Database configuration constants
define('DB_HOST', 'localhost:3306');
define('DB_NAME', 'encrypted_data');
define('DB_USER', 'root');
define('DB_PASS', '');

try {
    $pdo = new PDO("mysql:host=" . DB_HOST . ";dbname=" . DB_NAME, DB_USER, DB_PASS);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
    $conn = mysqli_connect(DB_HOST, DB_USER, DB_PASS, DB_NAME);
    if (!$conn) {
        throw new Exception("mysqli connection failed: " . mysqli_connect_error());
    }
} catch(Exception $e) {
    die("Connection failed: " . $e->getMessage());
}
?>
