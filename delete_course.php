<?php
session_start();
require 'db_conn.php';

// Fix: Check which variable name contains the connection
if (isset($pdo)) { $conn = $pdo; }
elseif (isset($db)) { $conn = $db; }

// Security: Only Admin can delete
if (!isset($_SESSION['role']) || $_SESSION['role'] !== 'admin') {
    header("Location: login.php");
    exit();
}

if (isset($_GET['id'])) {
    $id = $_GET['id'];

    // 1. Get image name to delete file from folder
    $stmt = $conn->prepare("SELECT thumbnail_image FROM courses WHERE id = ?");
    $stmt->execute([$id]);
    $course = $stmt->fetch();

    if ($course) {
        $image_path = "uploads/" . $course['thumbnail_image'];
        if (file_exists($image_path)) {
            unlink($image_path); // Delete file from server
        }
    }

    // 2. Delete from database
    $stmt = $conn->prepare("DELETE FROM courses WHERE id = ?");
    $stmt->execute([$id]);
}

header("Location: admin_dashboard.php?msg=CourseDeleted");
exit();
?>