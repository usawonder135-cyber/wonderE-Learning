<?php
// add_quiz.php - Admin: Add Quiz to Course
session_start();

// Check if user is logged in and is admin
if (!isset($_SESSION['user_id'], $_SESSION['role']) || $_SESSION['role'] !== 'admin') {
    header('Location: login.php');
    exit();
}

// Include database connection
require_once 'db_conn.php';

// Initialize variables
$course_id = 0;
$course = null;
$title = $description = '';
$error_message = '';
$success_message = '';

// Get course ID from URL
if (isset($_GET['course_id']) && is_numeric($_GET['course_id'])) {
    $course_id = intval($_GET['course_id']);
    
    // Fetch course details
    try {
        $stmt = $pdo->prepare("SELECT * FROM courses WHERE id = ?");
        $stmt->execute([$course_id]);
        $course = $stmt->fetch();
        
        if (!$course) {
            $error_message = "Course not found.";
        }
    } catch (PDOException $e) {
        error_log("Error fetching course: " . $e->getMessage());
        $error_message = "Unable to load course details.";
    }
} else {
    $error_message = "Invalid course ID.";
}

// Handle quiz creation
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['create_quiz'])) {
    $title = trim($_POST['title'] ?? '');
    $description = trim($_POST['description'] ?? '');
    $passing_score = intval($_POST['passing_score'] ?? 70);
    $time_limit = intval($_POST['time_limit'] ?? 30);
    
    // Validation
    if (empty($title)) {
        $error_message = "Quiz title is required.";
    } elseif ($passing_score < 1 || $passing_score > 100) {
        $error_message = "Passing score must be between 1 and 100.";
    } else {
        try {
            // Start transaction
            $pdo->beginTransaction();
            
            // Insert quiz
            $stmt = $pdo->prepare("INSERT INTO quizzes (course_id, title, description, passing_score, time_limit) 
                                   VALUES (?, ?, ?, ?, ?)");
            $stmt->execute([$course_id, $title, $description, $passing_score, $time_limit]);
            $quiz_id = $pdo->lastInsertId();
            
            // Update course has_quiz flag
            $stmt = $pdo->prepare("UPDATE courses SET has_quiz = TRUE WHERE id = ?");
            $stmt->execute([$course_id]);
            
            $pdo->commit();
            
            // Redirect to add questions page
            header('Location: add_quiz_questions.php?quiz_id=' . $quiz_id);
            exit();
            
        } catch (PDOException $e) {
            $pdo->rollBack();
            error_log("Quiz creation error: " . $e->getMessage());
            $error_message = "Failed to create quiz. Please try again.";
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Add Quiz - E-Learning Admin</title>
    <link rel="stylesheet" href="style.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
</head>
<body>
    <!-- Navigation -->
    <nav class="navbar">
        <div class="container">
            <div class="logo">
                <i class="fas fa-graduation-cap"></i>
                <span>E-Learn Admin</span>
            </div>
            <ul class="nav-links">
                <li><a href="admin_dashboard.php" class="nav-link"><i class="fas fa-tachometer-alt"></i> Dashboard</a></li>
                <li><a href="add_course.php" class="nav-link"><i class="fas fa-plus-circle"></i> Add Course</a></li>
                <li><a href="#" class="nav-link"><i class="fas fa-users"></i> Students</a></li>
                <li><a href="logout.php" class="btn btn-danger btn-sm"><i class="fas fa-sign-out-alt"></i> Logout</a></li>
            </ul>
        </div>
    </nav>

    <!-- Main Content -->
    <div class="container mt-4">
        <div class="row">
            <div class="col" style="max-width: 800px; margin: 0 auto;">
                <div class="card">
                    <!-- Header -->
                    <div class="card-header">
                        <h1><i class="fas fa-question-circle text-primary"></i> Create Quiz</h1>
                        <p class="text-secondary">
                            <?php if ($course): ?>
                                For Course: <strong><?php echo htmlspecialchars($course['title']); ?></strong>
                            <?php endif; ?>
                        </p>
                    </div>
                    
                    <!-- Display Error Message -->
                    <?php if ($error_message && !$course): ?>
                        <div class="alert alert-danger">
                            <i class="fas fa-exclamation-circle"></i> <?php echo $error_message; ?>
                            <div class="mt-3">
                                <a href="admin_dashboard.php" class="btn btn-primary">
                                    <i class="fas fa-arrow-left"></i> Back to Dashboard
                                </a>
                            </div>
                        </div>
                    <?php else: ?>
                        
                        <!-- Display Error Message (if any) -->
                        <?php if ($error_message): ?>
                            <div class="alert alert-danger">
                                <i class="fas fa-exclamation-circle"></i> <?php echo $error_message; ?>
                            </div>
                        <?php endif; ?>
                        
                        <!-- Quiz Form -->
                        <form method="POST" action="">
                            <div class="form-group">
                                <label for="title" class="form-label">
                                    <i class="fas fa-heading"></i> Quiz Title *
                                </label>
                                <input 
                                    type="text" 
                                    id="title" 
                                    name="title" 
                                    class="form-control" 
                                    placeholder="Enter quiz title (e.g., 'Final Assessment')"
                                    value="<?php echo htmlspecialchars($title); ?>"
                                    required
                                >
                            </div>
                            
                            <div class="form-group">
                                <label for="description" class="form-label">
                                    <i class="fas fa-align-left"></i> Quiz Description
                                </label>
                                <textarea 
                                    id="description" 
                                    name="description" 
                                    class="form-control" 
                                    placeholder="Describe what this quiz covers"
                                    rows="3"
                                ><?php echo htmlspecialchars($description); ?></textarea>
                            </div>
                            
                            <div class="row">
                                <div class="col">
                                    <div class="form-group">
                                        <label for="passing_score" class="form-label">
                                            <i class="fas fa-percentage"></i> Passing Score (%) *
                                        </label>
                                        <input 
                                            type="number" 
                                            id="passing_score" 
                                            name="passing_score" 
                                            class="form-control" 
                                            min="1"
                                            max="100"
                                            value="70"
                                            required
                                        >
                                        <small class="form-text">Minimum score required to pass</small>
                                    </div>
                                </div>
                                <div class="col">
                                    <div class="form-group">
                                        <label for="time_limit" class="form-label">
                                            <i class="fas fa-clock"></i> Time Limit (minutes)
                                        </label>
                                        <input 
                                            type="number" 
                                            id="time_limit" 
                                            name="time_limit" 
                                            class="form-control" 
                                            min="1"
                                            value="30"
                                            required
                                        >
                                        <small class="form-text">Set 0 for no time limit</small>
                                    </div>
                                </div>
                            </div>
                            
                            <!-- Form Actions -->
                            <div class="row mt-4">
                                <div class="col">
                                    <button type="submit" name="create_quiz" class="btn btn-primary btn-block btn-lg">
                                        <i class="fas fa-save"></i> Create Quiz & Add Questions
                                    </button>
                                </div>
                                <div class="col">
                                    <a href="edit_course.php?id=<?php echo $course_id; ?>" class="btn btn-secondary btn-block btn-lg">
                                        <i class="fas fa-times"></i> Cancel
                                    </a>
                                </div>
                            </div>
                        </form>
                        
                        <!-- Instructions -->
                        <div class="card mt-4" style="background-color: rgba(37, 99, 235, 0.05);">
                            <div class="card-header">
                                <h4><i class="fas fa-info-circle text-primary"></i> Quiz Creation Process</h4>
                            </div>
                            <div class="p-3">
                                <ol class="text-secondary">
                                    <li><strong>Step 1:</strong> Create quiz details (this page)</li>
                                    <li><strong>Step 2:</strong> Add multiple-choice questions</li>
                                    <li><strong>Step 3:</strong> Set correct answers</li>
                                    <li><strong>Step 4:</strong> Publish quiz to course</li>
                                    <li><strong>Note:</strong> Students need to pass this quiz to get certificates</li>
                                </ol>
                            </div>
                        </div>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    </div>

    <!-- Footer -->
    <footer class="footer mt-5">
        <div class="container">
            <div class="text-center">
                <p>© <?php echo date('Y'); ?> E-Learning Platform. Admin Panel.</p>
                <p class="text-secondary">
                    <i class="fas fa-user-tie"></i> 
                    Logged in as: <?php echo htmlspecialchars($_SESSION['full_name'] ?? 'Admin'); ?>
                </p>
            </div>
        </div>
    </footer>

    <script>
        // Form validation
        document.addEventListener('DOMContentLoaded', function() {
            const form = document.querySelector('form');
            const passingScore = document.getElementById('passing_score');
            const timeLimit = document.getElementById('time_limit');
            
            // Validate passing score
            passingScore.addEventListener('change', function() {
                if (this.value < 1 || this.value > 100) {
                    this.style.borderColor = '#ef4444';
                } else {
                    this.style.borderColor = '#e5e7eb';
                }
            });
            
            // Validate time limit
            timeLimit.addEventListener('change', function() {
                if (this.value < 0) {
                    this.style.borderColor = '#ef4444';
                } else {
                    this.style.borderColor = '#e5e7eb';
                }
            });
            
            // Form submission validation
            form.addEventListener('submit', function(e) {
                let isValid = true;
                
                // Check required fields
                const title = document.getElementById('title');
                if (title.value.trim().length === 0) {
                    alert('Quiz title is required.');
                    title.focus();
                    isValid = false;
                }
                
                if (passingScore.value < 1 || passingScore.value > 100) {
                    alert('Passing score must be between 1 and 100.');
                    passingScore.focus();
                    isValid = false;
                }
                
                if (timeLimit.value < 0) {
                    alert('Time limit cannot be negative.');
                    timeLimit.focus();
                    isValid = false;
                }
                
                if (!isValid) {
                    e.preventDefault();
                }
            });
        });
    </script>
</body>
</html>