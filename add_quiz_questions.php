<?php
// add_quiz_questions.php - Add Questions to Quiz
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
$quiz = null;
$course = null;
$questions = [];
$error_message = '';
$success_message = '';

// Get quiz ID from URL
if (isset($_GET['quiz_id']) && is_numeric($_GET['quiz_id'])) {
    $quiz_id = intval($_GET['quiz_id']);
    
    // Fetch quiz and course details
    try {
        $stmt = $pdo->prepare("SELECT q.*, c.title as course_title 
                               FROM quizzes q 
                               JOIN courses c ON q.course_id = c.id 
                               WHERE q.id = ?");
        $stmt->execute([$quiz_id]);
        $quiz = $stmt->fetch();
        
        if (!$quiz) {
            $error_message = "Quiz not found.";
        } else {
            // Fetch existing questions
            $stmt = $pdo->prepare("SELECT * FROM quiz_questions WHERE quiz_id = ? ORDER BY id");
            $stmt->execute([$quiz_id]);
            $questions = $stmt->fetchAll();
        }
    } catch (PDOException $e) {
        error_log("Error fetching quiz: " . $e->getMessage());
        $error_message = "Unable to load quiz details.";
    }
} else {
    $error_message = "Invalid quiz ID.";
}

// Handle adding new question
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    if (isset($_POST['add_question'])) {
        $question_text = trim($_POST['question_text'] ?? '');
        $question_type = $_POST['question_type'] ?? 'multiple_choice';
        $points = intval($_POST['points'] ?? 1);
        
        // Options for multiple choice
        $options = [];
        $correct_option = intval($_POST['correct_option'] ?? 1);
        
        for ($i = 1; $i <= 4; $i++) {
            $option_text = trim($_POST["option_$i"] ?? '');
            if (!empty($option_text)) {
                $options[$i] = [
                    'text' => $option_text,
                    'is_correct' => ($i == $correct_option)
                ];
            }
        }
        
        // Validation
        if (empty($question_text)) {
            $error_message = "Question text is required.";
        } elseif (count($options) < 2) {
            $error_message = "At least 2 options are required for multiple choice.";
        } elseif ($correct_option < 1 || $correct_option > count($options)) {
            $error_message = "Please select a correct option.";
        } else {
            try {
                // Start transaction
                $pdo->beginTransaction();
                
                // Insert question
                $stmt = $pdo->prepare("INSERT INTO quiz_questions (quiz_id, question_text, question_type, points) 
                                       VALUES (?, ?, ?, ?)");
                $stmt->execute([$quiz_id, $question_text, $question_type, $points]);
                $question_id = $pdo->lastInsertId();
                
                // Insert options
                foreach ($options as $option_num => $option) {
                    $stmt = $pdo->prepare("INSERT INTO quiz_options (question_id, option_text, is_correct) 
                                           VALUES (?, ?, ?)");
                    $stmt->execute([$question_id, $option['text'], $option['is_correct'] ? 1 : 0]);
                }
                
                // Update total questions count in quiz
                $stmt = $pdo->prepare("UPDATE quizzes SET total_questions = total_questions + 1 WHERE id = ?");
                $stmt->execute([$quiz_id]);
                
                $pdo->commit();
                
                $success_message = "Question added successfully!";
                
                // Refresh questions list
                $stmt = $pdo->prepare("SELECT * FROM quiz_questions WHERE quiz_id = ? ORDER BY id");
                $stmt->execute([$quiz_id]);
                $questions = $stmt->fetchAll();
                
            } catch (PDOException $e) {
                $pdo->rollBack();
                error_log("Question creation error: " . $e->getMessage());
                $error_message = "Failed to add question. Please try again.";
            }
        }
    } elseif (isset($_POST['publish_quiz'])) {
        // Mark quiz as active
        try {
            $stmt = $pdo->prepare("UPDATE quizzes SET is_active = TRUE WHERE id = ?");
            $stmt->execute([$quiz_id]);
            
            // Redirect to course edit page
            header('Location: edit_course.php?id=' . $quiz['course_id'] . '&msg=QuizPublished');
            exit();
            
        } catch (PDOException $e) {
            error_log("Quiz publish error: " . $e->getMessage());
            $error_message = "Failed to publish quiz.";
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Add Quiz Questions - E-Learning Admin</title>
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
            <div class="col" style="max-width: 1000px; margin: 0 auto;">
                <div class="card">
                    <!-- Header -->
                    <div class="card-header">
                        <div class="flex-between">
                            <div>
                                <h1><i class="fas fa-question-circle text-primary"></i> Add Quiz Questions</h1>
                                <p class="text-secondary">
                                    <?php if ($quiz): ?>
                                        Quiz: <strong><?php echo htmlspecialchars($quiz['title']); ?></strong> | 
                                        Course: <strong><?php echo htmlspecialchars($quiz['course_title']); ?></strong>
                                    <?php endif; ?>
                                </p>
                            </div>
                            <div>
                                <div class="badge badge-primary">
                                    <i class="fas fa-list-ol"></i> <?php echo count($questions); ?> Questions
                                </div>
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
                        
                        <!-- Existing Questions -->
                        <?php if (!empty($questions)): ?>
                            <div class="card mb-4">
                                <div class="card-header">
                                    <h3><i class="fas fa-list text-success"></i> Current Questions (<?php echo count($questions); ?>)</h3>
                                </div>
                                <div class="p-3">
                                    <div class="table-responsive">
                                        <table class="table">
                                            <thead>
                                                <tr>
                                                    <th>#</th>
                                                    <th>Question</th>
                                                    <th>Type</th>
                                                    <th>Points</th>
                                                    <th>Options</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                <?php foreach ($questions as $index => $question): 
                                                    // Get options for this question
                                                    $stmt = $pdo->prepare("SELECT * FROM quiz_options WHERE question_id = ?");
                                                    $stmt->execute([$question['id']]);
                                                    $options = $stmt->fetchAll();
                                                ?>
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
                                                                <?php foreach ($options as $option): ?>
                                                                    <li>
                                                                        <?php echo htmlspecialchars($option['option_text']); ?>
                                                                        <?php if ($option['is_correct']): ?>
                                                                            <span class="badge badge-success ml-2">Correct</span>
                                                                        <?php endif; ?>
                                                                    </li>
                                                                <?php endforeach; ?>
                                                            </ul>
                                                        </td>
                                                    </tr>
                                                <?php endforeach; ?>
                                            </tbody>
                                        </table>
                                    </div>
                                </div>
                            </div>
                        <?php endif; ?>
                        
                        <!-- Add New Question Form -->
                        <div class="card mb-4">
                            <div class="card-header">
                                <h3><i class="fas fa-plus-circle text-primary"></i> Add New Question</h3>
                            </div>
                            <div class="p-3">
                                <form method="POST" action="">
                                    <div class="form-group">
                                        <label for="question_text" class="form-label">Question Text *</label>
                                        <textarea 
                                            id="question_text" 
                                            name="question_text" 
                                            class="form-control" 
                                            placeholder="Enter your question here..."
                                            rows="3"
                                            required
                                        ></textarea>
                                    </div>
                                    
                                    <div class="row">
                                        <div class="col">
                                            <div class="form-group">
                                                <label for="question_type" class="form-label">Question Type</label>
                                                <select id="question_type" name="question_type" class="form-control">
                                                    <option value="multiple_choice">Multiple Choice</option>
                                                    <option value="true_false">True/False</option>
                                                </select>
                                            </div>
                                        </div>
                                        <div class="col">
                                            <div class="form-group">
                                                <label for="points" class="form-label">Points</label>
                                                <input 
                                                    type="number" 
                                                    id="points" 
                                                    name="points" 
                                                    class="form-control" 
                                                    min="1"
                                                    value="1"
                                                    required
                                                >
                                            </div>
                                        </div>
                                    </div>
                                    
                                    <!-- Multiple Choice Options -->
                                    <div id="multiple_choice_options">
                                        <h4 class="mt-4 mb-3">Multiple Choice Options</h4>
                                        
                                        <?php for ($i = 1; $i <= 4; $i++): ?>
                                            <div class="form-group">
                                                <div class="input-group">
                                                    <div class="input-group-prepend">
                                                        <div class="input-group-text">
                                                            <input type="radio" name="correct_option" value="<?php echo $i; ?>" 
                                                                   <?php echo $i == 1 ? 'checked' : ''; ?>>
                                                        </div>
                                                    </div>
                                                    <input 
                                                        type="text" 
                                                        name="option_<?php echo $i; ?>"
                                                        class="form-control" 
                                                        placeholder="Option <?php echo $i; ?>"
                                                        required
                                                    >
                                                    <div class="input-group-append">
                                                        <span class="input-group-text">
                                                            <?php if ($i == 1): ?>
                                                                <span class="badge badge-success">Correct</span>
                                                            <?php endif; ?>
                                                        </span>
                                                    </div>
                                                </div>
                                            </div>
                                        <?php endfor; ?>
                                        
                                        <small class="text-secondary">
                                            <i class="fas fa-info-circle"></i> Select the radio button next to the correct answer
                                        </small>
                                    </div>
                                    
                                    <!-- Form Actions -->
                                    <div class="row mt-4">
                                        <div class="col">
                                            <button type="submit" name="add_question" class="btn btn-primary btn-block btn-lg">
                                                <i class="fas fa-plus"></i> Add Question
                                            </button>
                                        </div>
                                        <div class="col">
                                            <?php if (count($questions) >= 5): ?>
                                                <button type="submit" name="publish_quiz" class="btn btn-success btn-block btn-lg">
                                                    <i class="fas fa-check-circle"></i> Publish Quiz
                                                </button>
                                            <?php else: ?>
                                                <button type="button" class="btn btn-secondary btn-block btn-lg" disabled>
                                                    <i class="fas fa-check-circle"></i> Add <?php echo 5 - count($questions); ?> more questions to publish
                                                </button>
                                            <?php endif; ?>
                                        </div>
                                        <div class="col">
                                            <a href="edit_course.php?id=<?php echo $quiz['course_id'] ?? ''; ?>" class="btn btn-warning btn-block btn-lg">
                                                <i class="fas fa-times"></i> Finish Later
                                            </a>
                                        </div>
                                    </div>
                                </form>
                            </div>
                        </div>
                        
                        <!-- Instructions -->
                        <div class="card" style="background-color: rgba(37, 99, 235, 0.05);">
                            <div class="card-header">
                                <h4><i class="fas fa-info-circle text-primary"></i> Quiz Creation Guidelines</h4>
                            </div>
                            <div class="p-3">
                                <ol class="text-secondary">
                                    <li><strong>Minimum Questions:</strong> At least 5 questions required to publish quiz</li>
                                    <li><strong>Question Types:</strong> Multiple Choice (4 options, 1 correct) or True/False</li>
                                    <li><strong>Points:</strong> Assign points based on question difficulty (default: 1 point)</li>
                                    <li><strong>Passing Score:</strong> Students need <?php echo $quiz['passing_score'] ?? 70; ?>% to pass</li>
                                    <li><strong>Time Limit:</strong> Quiz has <?php echo $quiz['time_limit'] ?? 30; ?> minute time limit</li>
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
        // Toggle question type options
        document.addEventListener('DOMContentLoaded', function() {
            const questionType = document.getElementById('question_type');
            const mcOptions = document.getElementById('multiple_choice_options');
            
            function toggleOptions() {
                if (questionType.value === 'true_false') {
                    mcOptions.style.display = 'none';
                    // We would add true/false options here
                } else {
                    mcOptions.style.display = 'block';
                }
            }
            
            questionType.addEventListener('change', toggleOptions);
            toggleOptions(); // Initial call
            
            // Form validation
            const form = document.querySelector('form');
            form.addEventListener('submit', function(e) {
                const questionText = document.getElementById('question_text');
                const points = document.getElementById('points');
                
                let isValid = true;
                
                if (questionText.value.trim().length === 0) {
                    alert('Question text is required.');
                    questionText.focus();
                    isValid = false;
                }
                
                if (points.value < 1) {
                    alert('Points must be at least 1.');
                    points.focus();
                    isValid = false;
                }
                
                // Validate at least 2 options are filled for multiple choice
                if (questionType.value === 'multiple_choice') {
                    let filledOptions = 0;
                    for (let i = 1; i <= 4; i++) {
                        const option = document.querySelector(`[name="option_${i}"]`);
                        if (option && option.value.trim().length > 0) {
                            filledOptions++;
                        }
                    }
                    
                    if (filledOptions < 2) {
                        alert('At least 2 options must be filled for multiple choice questions.');
                        isValid = false;
                    }
                }
                
                if (!isValid) {
                    e.preventDefault();
                }
            });
        });
    </script>
</body>
</html>