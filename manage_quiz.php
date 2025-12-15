<?php
// manage_quiz.php - Manage Quiz Questions and Settings
session_start();

// Check if user is logged in and is admin
if (!isset($_SESSION['user_id'], $_SESSION['role']) || $_SESSION['role'] !== 'admin') {
    header('Location: login.php');
    exit();
}

// Include database connection
require_once 'db_conn.php';

// Initialize variables
$quiz_id = 0;
$course_id = 0;
$quiz = null;
$course = null;
$questions = [];
$error_message = '';
$success_message = '';

// Get quiz ID from URL
if (isset($_GET['course_id']) && is_numeric($_GET['course_id'])) {
    $course_id = intval($_GET['course_id']);
    
    // Fetch quiz for this course
    try {
        $stmt = $pdo->prepare("SELECT q.*, c.title as course_title 
                               FROM quizzes q 
                               JOIN courses c ON q.course_id = c.id 
                               WHERE q.course_id = ?");
        $stmt->execute([$course_id]);
        $quiz = $stmt->fetch();
        
        if ($quiz) {
            $quiz_id = $quiz['id'];
            
            // Fetch all questions with options
            $stmt = $pdo->prepare("
                SELECT qq.*, 
                       GROUP_CONCAT(
                           CONCAT(qo.option_text, '::', qo.is_correct) 
                           ORDER BY qo.id SEPARATOR '||'
                       ) as options
                FROM quiz_questions qq
                LEFT JOIN quiz_options qo ON qq.id = qo.question_id
                WHERE qq.quiz_id = ?
                GROUP BY qq.id
                ORDER BY qq.id
            ");
            $stmt->execute([$quiz_id]);
            $questions = $stmt->fetchAll();
            
            // Process options
            foreach ($questions as &$question) {
                $options = [];
                if ($question['options']) {
                    $optionPairs = explode('||', $question['options']);
                    foreach ($optionPairs as $optionPair) {
                        list($text, $is_correct) = explode('::', $optionPair);
                        $options[] = [
                            'text' => $text,
                            'is_correct' => $is_correct
                        ];
                    }
                }
                $question['options_list'] = $options;
            }
        } else {
            $error_message = "No quiz found for this course.";
        }
    } catch (PDOException $e) {
        error_log("Error fetching quiz: " . $e->getMessage());
        $error_message = "Unable to load quiz details.";
    }
} else {
    $error_message = "Invalid course ID.";
}

// Handle quiz status toggle
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    if (isset($_POST['toggle_status'])) {
        try {
            $new_status = $quiz['is_active'] ? 0 : 1;
            $stmt = $pdo->prepare("UPDATE quizzes SET is_active = ? WHERE id = ?");
            $stmt->execute([$new_status, $quiz_id]);
            
            $success_message = $new_status ? "Quiz activated successfully!" : "Quiz deactivated successfully!";
            
            // Refresh quiz data
            $stmt = $pdo->prepare("SELECT * FROM quizzes WHERE id = ?");
            $stmt->execute([$quiz_id]);
            $quiz = $stmt->fetch();
            
        } catch (PDOException $e) {
            error_log("Quiz status toggle error: " . $e->getMessage());
            $error_message = "Failed to update quiz status.";
        }
    }
    
    // Handle question deletion
    if (isset($_POST['delete_question']) && isset($_POST['question_id'])) {
        $question_id = intval($_POST['question_id']);
        
        try {
            $pdo->beginTransaction();
            
            // Delete question options first
            $stmt = $pdo->prepare("DELETE FROM quiz_options WHERE question_id = ?");
            $stmt->execute([$question_id]);
            
            // Delete question
            $stmt = $pdo->prepare("DELETE FROM quiz_questions WHERE id = ?");
            $stmt->execute([$question_id]);
            
            // Update total questions count
            $stmt = $pdo->prepare("UPDATE quizzes SET total_questions = total_questions - 1 WHERE id = ?");
            $stmt->execute([$quiz_id]);
            
            $pdo->commit();
            
            $success_message = "Question deleted successfully!";
            
            // Refresh questions list
            $stmt = $pdo->prepare("
                SELECT qq.*, 
                       GROUP_CONCAT(
                           CONCAT(qo.option_text, '::', qo.is_correct) 
                           ORDER BY qo.id SEPARATOR '||'
                       ) as options
                FROM quiz_questions qq
                LEFT JOIN quiz_options qo ON qq.id = qo.question_id
                WHERE qq.quiz_id = ?
                GROUP BY qq.id
                ORDER BY qq.id
            ");
            $stmt->execute([$quiz_id]);
            $questions = $stmt->fetchAll();
            
        } catch (PDOException $e) {
            $pdo->rollBack();
            error_log("Question deletion error: " . $e->getMessage());
            $error_message = "Failed to delete question.";
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Manage Quiz - E-Learning Admin</title>
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
            <div class="col" style="max-width: 1200px; margin: 0 auto;">
                <div class="card">
                    <!-- Header -->
                    <div class="card-header">
                        <div class="flex-between">
                            <div>
                                <h1><i class="fas fa-cogs text-primary"></i> Manage Quiz</h1>
                                <p class="text-secondary">
                                    <?php if ($quiz): ?>
                                        Course: <strong><?php echo htmlspecialchars($quiz['course_title']); ?></strong> | 
                                        Quiz: <strong><?php echo htmlspecialchars($quiz['title']); ?></strong>
                                    <?php endif; ?>
                                </p>
                            </div>
                            <div>
                                <a href="edit_course.php?id=<?php echo $course_id; ?>" class="btn btn-secondary">
                                    <i class="fas fa-arrow-left"></i> Back to Course
                                </a>
                                <a href="add_quiz_questions.php?quiz_id=<?php echo $quiz_id; ?>" class="btn btn-success">
                                    <i class="fas fa-plus"></i> Add More Questions
                                </a>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Display Messages -->
                    <?php if ($error_message && !$quiz): ?>
                        <div class="alert alert-danger">
                            <i class="fas fa-exclamation-circle"></i> <?php echo $error_message; ?>
                            <div class="mt-3">
                                <a href="admin_dashboard.php" class="btn btn-primary">
                                    <i class="fas fa-arrow-left"></i> Back to Dashboard
                                </a>
                            </div>
                        </div>
                    <?php else: ?>
                        
                        <!-- Display Error/Success Messages -->
                        <?php if ($error_message): ?>
                            <div class="alert alert-danger">
                                <i class="fas fa-exclamation-circle"></i> <?php echo $error_message; ?>
                            </div>
                        <?php endif; ?>
                        
                        <?php if ($success_message): ?>
                            <div class="alert alert-success">
                                <i class="fas fa-check-circle"></i> <?php echo $success_message; ?>
                            </div>
                        <?php endif; ?>
                        
                        <!-- Quiz Summary Card -->
                        <div class="card mb-4">
                            <div class="card-header">
                                <h3><i class="fas fa-chart-bar text-info"></i> Quiz Summary</h3>
                            </div>
                            <div class="p-3">
                                <div class="row text-center">
                                    <div class="col">
                                        <div class="stat-card">
                                            <h2><?php echo $quiz['total_questions'] ?? 0; ?></h2>
                                            <p>Total Questions</p>
                                        </div>
                                    </div>
                                    <div class="col">
                                        <div class="stat-card">
                                            <h2><?php echo $quiz['passing_score'] ?? 70; ?>%</h2>
                                            <p>Passing Score</p>
                                        </div>
                                    </div>
                                    <div class="col">
                                        <div class="stat-card">
                                            <h2><?php echo $quiz['time_limit'] ?? 30; ?></h2>
                                            <p>Time Limit (min)</p>
                                        </div>
                                    </div>
                                    <div class="col">
                                        <div class="stat-card">
                                            <h2>
                                                <?php if ($quiz['is_active']): ?>
                                                    <span class="badge badge-success">Active</span>
                                                <?php else: ?>
                                                    <span class="badge badge-danger">Inactive</span>
                                                <?php endif; ?>
                                            </h2>
                                            <p>Status</p>
                                        </div>
                                    </div>
                                </div>
                                
                                <!-- Quiz Actions -->
                                <div class="row mt-4">
                                    <div class="col">
                                        <form method="POST" class="d-inline">
                                            <button type="submit" name="toggle_status" class="btn <?php echo $quiz['is_active'] ? 'btn-warning' : 'btn-success'; ?> btn-lg">
                                                <i class="fas fa-power-off"></i> 
                                                <?php echo $quiz['is_active'] ? 'Deactivate Quiz' : 'Activate Quiz'; ?>
                                            </button>
                                        </form>
                                        <a href="add_quiz_questions.php?quiz_id=<?php echo $quiz_id; ?>" class="btn btn-primary btn-lg ml-2">
                                            <i class="fas fa-edit"></i> Edit Questions
                                        </a>
                                        <button class="btn btn-info btn-lg ml-2" onclick="showQuizSettings()">
                                            <i class="fas fa-cog"></i> Quiz Settings
                                        </button>
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                        <!-- Questions List -->
                        <div class="card">
                            <div class="card-header">
                                <h3><i class="fas fa-list text-success"></i> Quiz Questions (<?php echo count($questions); ?>)</h3>
                            </div>
                            <div class="p-3">
                                <?php if (!empty($questions)): ?>
                                    <div class="table-responsive">
                                        <table class="table">
                                            <thead>
                                                <tr>
                                                    <th>#</th>
                                                    <th>Question</th>
                                                    <th>Type</th>
                                                    <th>Points</th>
                                                    <th>Options</th>
                                                    <th>Actions</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                <?php foreach ($questions as $index => $question): ?>
                                                    <tr>
                                                        <td><?php echo $index + 1; ?></td>
                                                        <td>
                                                            <strong><?php echo htmlspecialchars($question['question_text']); ?></strong>
                                                        </td>
                                                        <td>
                                                            <span class="badge badge-info">
                                                                <?php echo ucfirst(str_replace('_', ' ', $question['question_type'])); ?>
                                                            </span>
                                                        </td>
                                                        <td><?php echo $question['points']; ?></td>
                                                        <td>
                                                            <ul class="list-unstyled mb-0">
                                                                <?php if (!empty($question['options_list'])): ?>
                                                                    <?php foreach ($question['options_list'] as $option): ?>
                                                                        <li>
                                                                            <?php echo htmlspecialchars($option['text']); ?>
                                                                            <?php if ($option['is_correct']): ?>
                                                                                <span class="badge badge-success ml-2">Correct</span>
                                                                            <?php endif; ?>
                                                                        </li>
                                                                    <?php endforeach; ?>
                                                                <?php else: ?>
                                                                    <li><em>No options</em></li>
                                                                <?php endif; ?>
                                                            </ul>
                                                        </td>
                                                        <td>
                                                            <div class="btn-group">
                                                                <button class="btn btn-sm btn-info" onclick="editQuestion(<?php echo $question['id']; ?>)">
                                                                    <i class="fas fa-edit"></i>
                                                                </button>
                                                                <form method="POST" class="d-inline" onsubmit="return confirmDelete();">
                                                                    <input type="hidden" name="question_id" value="<?php echo $question['id']; ?>">
                                                                    <button type="submit" name="delete_question" class="btn btn-sm btn-danger">
                                                                        <i class="fas fa-trash"></i>
                                                                    </button>
                                                                </form>
                                                            </div>
                                                        </td>
                                                    </tr>
                                                <?php endforeach; ?>
                                            </tbody>
                                        </table>
                                    </div>
                                <?php else: ?>
                                    <div class="alert alert-warning">
                                        <i class="fas fa-exclamation-triangle"></i> No questions found. 
                                        <a href="add_quiz_questions.php?quiz_id=<?php echo $quiz_id; ?>" class="btn btn-sm btn-success ml-2">
                                            Add Questions
                                        </a>
                                    </div>
                                <?php endif; ?>
                            </div>
                        </div>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    </div>

    <!-- Quiz Settings Modal -->
    <div id="quizSettingsModal" class="modal" style="display: none;">
        <div class="modal-content" style="max-width: 600px;">
            <div class="modal-header">
                <h3><i class="fas fa-cog text-primary"></i> Quiz Settings</h3>
                <button class="close-btn" onclick="closeModal()">&times;</button>
            </div>
            <div class="modal-body">
                <?php if ($quiz): ?>
                    <form id="quizSettingsForm" method="POST" action="update_quiz_settings.php">
                        <input type="hidden" name="quiz_id" value="<?php echo $quiz_id; ?>">
                        
                        <div class="form-group">
                            <label class="form-label">Quiz Title</label>
                            <input type="text" name="title" class="form-control" value="<?php echo htmlspecialchars($quiz['title']); ?>">
                        </div>
                        
                        <div class="form-group">
                            <label class="form-label">Description</label>
                            <textarea name="description" class="form-control" rows="3"><?php echo htmlspecialchars($quiz['description']); ?></textarea>
                        </div>
                        
                        <div class="row">
                            <div class="col">
                                <div class="form-group">
                                    <label class="form-label">Passing Score (%)</label>
                                    <input type="number" name="passing_score" class="form-control" 
                                           min="1" max="100" value="<?php echo $quiz['passing_score']; ?>">
                                </div>
                            </div>
                            <div class="col">
                                <div class="form-group">
                                    <label class="form-label">Time Limit (minutes)</label>
                                    <input type="number" name="time_limit" class="form-control" 
                                           min="0" value="<?php echo $quiz['time_limit']; ?>">
                                    <small>Set 0 for no time limit</small>
                                </div>
                            </div>
                        </div>
                        
                        <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" onclick="closeModal()">Cancel</button>
                            <button type="submit" class="btn btn-primary">Save Changes</button>
                        </div>
                    </form>
                <?php endif; ?>
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
        // Modal functions
        function showQuizSettings() {
            document.getElementById('quizSettingsModal').style.display = 'block';
        }
        
        function closeModal() {
            document.getElementById('quizSettingsModal').style.display = 'none';
        }
        
        function editQuestion(questionId) {
            alert('Edit feature coming soon! Question ID: ' + questionId);
            // Future implementation: Open edit question modal
        }
        
        function confirmDelete() {
            return confirm('Are you sure you want to delete this question? This action cannot be undone.');
        }
        
        // Close modal when clicking outside
        window.onclick = function(event) {
            const modal = document.getElementById('quizSettingsModal');
            if (event.target === modal) {
                closeModal();
            }
        }
        
        // Form validation for quiz settings
        document.getElementById('quizSettingsForm')?.addEventListener('submit', function(e) {
            const passingScore = this.querySelector('[name="passing_score"]');
            const timeLimit = this.querySelector('[name="time_limit"]');
            
            if (passingScore.value < 1 || passingScore.value > 100) {
                alert('Passing score must be between 1 and 100.');
                passingScore.focus();
                e.preventDefault();
            }
            
            if (timeLimit.value < 0) {
                alert('Time limit cannot be negative.');
                timeLimit.focus();
                e.preventDefault();
            }
        });
    </script>
    
    <style>
        /* Modal Styles */
        .modal {
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0,0,0,0.5);
            padding-top: 60px;
        }
        
        .modal-content {
            background-color: white;
            margin: 5% auto;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.2);
        }
        
        .modal-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid #e5e7eb;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }
        
        .close-btn {
            background: none;
            border: none;
            font-size: 24px;
            cursor: pointer;
            color: #6b7280;
        }
        
        .close-btn:hover {
            color: #374151;
        }
        
        .modal-footer {
            margin-top: 20px;
            padding-top: 15px;
            border-top: 1px solid #e5e7eb;
            text-align: right;
        }
        
        /* Stat Cards */
        .stat-card {
            padding: 20px;
            background: #f8fafc;
            border-radius: 8px;
            border: 1px solid #e2e8f0;
        }
        
        .stat-card h2 {
            margin: 0;
            color: #2563eb;
            font-size: 2.5rem;
        }
        
        .stat-card p {
            margin: 5px 0 0 0;
            color: #64748b;
            font-size: 0.9rem;
        }
        
        .flex-between {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
    </style>
</body>
</html>