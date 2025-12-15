<?php
// update_quiz_settings.php - Update Quiz Settings
session_start();

// Check if user is logged in and is admin
if (!isset($_SESSION['user_id'], $_SESSION['role']) || $_SESSION['role'] !== 'admin') {
    header('Location: login.php');
    exit();
}

require_once 'db_conn.php';

if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['quiz_id'])) {
    $quiz_id = intval($_POST['quiz_id']);
    $title = trim($_POST['title'] ?? '');
    $description = trim($_POST['description'] ?? '');
    $passing_score = intval($_POST['passing_score'] ?? 70);
    $time_limit = intval($_POST['time_limit'] ?? 30);
    
    try {
        $stmt = $pdo->prepare("UPDATE quizzes SET title = ?, description = ?, passing_score = ?, time_limit = ? WHERE id = ?");
        $stmt->execute([$title, $description, $passing_score, $time_limit, $quiz_id]);
        
        // Get course_id to redirect back
        $stmt = $pdo->prepare("SELECT course_id FROM quizzes WHERE id = ?");
        $stmt->execute([$quiz_id]);
        $quiz = $stmt->fetch();
        
        if ($quiz) {
            header('Location: manage_quiz.php?course_id=' . $quiz['course_id'] . '&msg=SettingsUpdated');
        } else {
            header('Location: admin_dashboard.php');
        }
        exit();
        
    } catch (PDOException $e) {
        error_log("Quiz settings update error: " . $e->getMessage());
        header('Location: manage_quiz.php?course_id=' . $_POST['course_id'] . '&error=UpdateFailed');
        exit();
    }
} else {
    header('Location: admin_dashboard.php');
    exit();
}
?>