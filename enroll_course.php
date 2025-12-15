<?php
// enroll_course.php - Handle course enrollment via AJAX
session_start();

// Check if user is logged in as student
if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'student') {
    echo json_encode(['success' => false, 'message' => 'Unauthorized']);
    exit();
}

// Check if course_id is provided
if (!isset($_POST['course_id']) || !is_numeric($_POST['course_id'])) {
    echo json_encode(['success' => false, 'message' => 'Invalid course']);
    exit();
}

$user_id = $_SESSION['user_id'];
$course_id = intval($_POST['course_id']);

// Include database connection
require_once 'db_conn.php';

try {
    // Check if already enrolled
    $stmt = $pdo->prepare("SELECT id FROM enrollments WHERE user_id = ? AND course_id = ?");
    $stmt->execute([$user_id, $course_id]);
    
    if ($stmt->fetch()) {
        echo json_encode(['success' => false, 'message' => 'Already enrolled']);
        exit();
    }
    
    // Insert enrollment
    $stmt = $pdo->prepare("INSERT INTO enrollments (user_id, course_id, enrollment_date) VALUES (?, ?, NOW())");
    $stmt->execute([$user_id, $course_id]);
    
    echo json_encode(['success' => true, 'message' => 'Enrolled successfully']);
    
} catch (PDOException $e) {
    error_log("Enrollment Error: " . $e->getMessage());
    echo json_encode(['success' => false, 'message' => 'Database error']);
}
?>