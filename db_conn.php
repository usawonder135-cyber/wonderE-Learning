<?php
// db_conn.php - Database connection using PDO
$host = 'localhost';
$dbname = 'e_learning';
$username = 'root';
$password = '';

try {
    $pdo = new PDO("mysql:host=$host;dbname=$dbname;charset=utf8mb4", $username, $password);

    // Set PDO error mode to exception
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    // Set default fetch mode to associative array
    $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);

    // Optional: Set timezone if needed
    // $pdo->exec("SET time_zone = '+00:00'");

    // echo "Database connection successful!"; // Remove in production

} catch (PDOException $e) {
    // Log error and show user-friendly message
    error_log("Database Connection Failed: " . $e->getMessage());
    die("Sorry, we're experiencing technical difficulties. Please try again later.");
}
