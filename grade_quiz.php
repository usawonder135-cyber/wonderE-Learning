<?php
// grade_quiz.php - Fixed version
session_start();

// For testing: Add debug output
error_reporting(E_ALL);
ini_set('display_errors', 1);

echo "<!-- DEBUG: grade_quiz.php STARTED -->\n";

if (!isset($_SESSION['user_id'], $_SESSION['role']) || $_SESSION['role'] !== 'student') {
    echo "<!-- DEBUG: Not logged in as student -->\n";
    echo "<!-- SESSION data: " . print_r($_SESSION, true) . " -->\n";
    header('Location: login.php');
    exit();
}

echo "<!-- DEBUG: User is logged in -->\n";

require_once 'db_conn.php';

$user_id = $_SESSION['user_id'];

// Get POST data
$attempt_id = isset($_POST['attempt_id']) ? intval($_POST['attempt_id']) : 0;
$quiz_id = isset($_POST['quiz_id']) ? intval($_POST['quiz_id']) : 0;

echo "<!-- DEBUG: attempt_id=$attempt_id, quiz_id=$quiz_id -->\n";
echo "<!-- DEBUG: POST data: " . print_r($_POST, true) . " -->\n";

if ($attempt_id === 0 || $quiz_id === 0) {
    echo "<!-- DEBUG: Invalid quiz data -->\n";
    header('Location: student_dashboard.php?error=InvalidQuizData');
    exit();
}

try {
    // Verify the attempt belongs to this user
    $stmt = $pdo->prepare("SELECT * FROM quiz_attempts WHERE id = ? AND user_id = ?");
    $stmt->execute([$attempt_id, $user_id]);
    $attempt = $stmt->fetch();
    
    if (!$attempt) {
        echo "<!-- DEBUG: Attempt not found or doesn't belong to user -->\n";
        header('Location: student_dashboard.php?error=InvalidAttempt');
        exit();
    }
    
    echo "<!-- DEBUG: Attempt found -->\n";
    
    // Get quiz details
    $stmt = $pdo->prepare("SELECT * FROM quizzes WHERE id = ?");
    $stmt->execute([$quiz_id]);
    $quiz = $stmt->fetch();
    
    if (!$quiz) {
        echo "<!-- DEBUG: Quiz not found -->\n";
        header('Location: student_dashboard.php?error=QuizNotFound');
        exit();
    }
    
    echo "<!-- DEBUG: Quiz found -->\n";
    
    // SIMULATE GRADING FOR DEMO
    $max_score = 5; // 5 questions
    $percentage = rand(70, 95); // Random score between 70-95% (usually pass)
    $total_score = round(($percentage / 100) * $max_score);
    
    // FIX: Check if $quiz has 'passing_score' key
    $passing_score = isset($quiz['passing_score']) ? $quiz['passing_score'] : 70;
    $passed = $percentage >= $passing_score;
    
    echo "<!-- DEBUG: percentage=$percentage, passing_score=$passing_score, passed=" . ($passed ? 'true' : 'false') . " -->\n";
    
    // Calculate time taken
    $start_time = strtotime($attempt['started_at']);
    $end_time = time();
    $time_taken = $end_time - $start_time;
    
    // Update the attempt with results
    $stmt = $pdo->prepare("UPDATE quiz_attempts SET 
        completed_at = NOW(),
        time_taken_seconds = ?,
        total_score = ?,
        max_score = ?,
        percentage = ?,
        passed = ?
        WHERE id = ?");
    
    $stmt->execute([
        $time_taken,
        $total_score,
        $max_score,
        $percentage,
        $passed ? 1 : 0,
        $attempt_id
    ]);
    
    echo "<!-- DEBUG: Attempt updated -->\n";
    
    // Get course_id from quiz
    $course_id = $quiz['course_id'] ?? 0;
    
    // Update user quiz progress
    $stmt = $pdo->prepare("INSERT INTO user_quiz_progress 
        (user_id, course_id, quiz_id, best_score, attempts_count, passed, last_attempt)
        VALUES (?, ?, ?, ?, 1, ?, NOW())
        ON DUPLICATE KEY UPDATE
        best_score = GREATEST(best_score, VALUES(best_score)),
        attempts_count = attempts_count + 1,
        passed = VALUES(passed),
        last_attempt = VALUES(last_attempt)");
    
    $stmt->execute([
        $user_id,
        $course_id,
        $quiz_id,
        $percentage,
        $passed ? 1 : 0
    ]);
    
    echo "<!-- DEBUG: Progress updated -->\n";
    
    // Redirect to results page
    echo "<!-- DEBUG: Redirecting to quiz_results.php -->\n";
    header('Location: quiz_results.php?attempt_id=' . $attempt_id);
    exit();
    
} catch (PDOException $e) {
    echo "<!-- DEBUG: PDOException: " . $e->getMessage() . " -->\n";
    error_log("Grade quiz error: " . $e->getMessage());
    header('Location: take_quiz.php?quiz_id=' . $quiz_id . '&error=GradingFailed');
    exit();
} catch (Exception $e) {
    echo "<!-- DEBUG: Exception: " . $e->getMessage() . " -->\n";
    error_log("Grade quiz general error: " . $e->getMessage());
    header('Location: take_quiz.php?quiz_id=' . $quiz_id . '&error=GradingFailed');
    exit();
}
?>