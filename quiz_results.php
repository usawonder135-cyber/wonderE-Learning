<?php
// quiz_results.php - Display quiz results
session_start();
// DEMO MODE: If no attempt_id provided, show demo results
if (!isset($_GET['attempt_id']) || empty($_GET['attempt_id'])) {
    // Create demo data for presentation
    $attempt = [
        'percentage' => 85,
        'total_score' => 4,
        'max_score' => 5,
        'time_taken_seconds' => 325,
        'passed' => 1,
        'quiz_title' => 'Python Basics Assessment',
        'course_title' => 'Introduction to Python',
        'passing_score' => 70
    ];
    
    // Use this demo data
    $_GET['attempt_id'] = 'demo_123';
}
require_once 'db_conn.php';


if (!isset($_SESSION['user_id'], $_SESSION['role']) || $_SESSION['role'] !== 'student') {
    header('Location: login.php');
    exit();
}

$attempt_id = isset($_GET['attempt_id']) ? intval($_GET['attempt_id']) : 0;
$user_id = $_SESSION['user_id'];

// Fetch attempt details
try {
    $stmt = $pdo->prepare("SELECT qa.*, q.title as quiz_title, q.passing_score, q.course_id, 
                          c.title as course_title 
                          FROM quiz_attempts qa
                          JOIN quizzes q ON qa.quiz_id = q.id
                          JOIN courses c ON q.course_id = c.id
                          WHERE qa.id = ? AND qa.user_id = ?");
    $stmt->execute([$attempt_id, $user_id]);
    $attempt = $stmt->fetch();

    if (!$attempt) {
        header('Location: my_courses.php');
        exit();
    }

    // Fetch answers with question details
    $stmt = $pdo->prepare("SELECT qa.*, qq.question_text, qq.points as max_points, 
                          qo.option_text as selected_option,
                          qo_correct.option_text as correct_option
                          FROM quiz_answers qa
                          JOIN quiz_questions qq ON qa.question_id = qq.id
                          LEFT JOIN quiz_options qo ON qa.selected_option_id = qo.id
                          LEFT JOIN quiz_options qo_correct ON qo_correct.question_id = qq.id AND qo_correct.is_correct = 1
                          WHERE qa.attempt_id = ?
                          ORDER BY qq.id");
    $stmt->execute([$attempt_id]);
    $answers = $stmt->fetchAll();
} catch (PDOException $e) {
    error_log("Results loading error: " . $e->getMessage());
    header('Location: my_courses.php?error=ResultsLoadFailed');
    exit();
}
?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Quiz Results - <?php echo htmlspecialchars($attempt['quiz_title']); ?></title>
    <link rel="stylesheet" href="style.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
</head>

<body>
    <nav class="navbar">
        <div class="container">
            <div class="logo">
                <i class="fas fa-graduation-cap"></i>
                <span>E-Learn Student</span>
            </div>
            <ul class="nav-links">
                <li><a href="student_dashboard.php" class="nav-link"><i class="fas fa-home"></i> Dashboard</a></li>
                <li><a href="my_courses.php" class="nav-link"><i class="fas fa-book-open"></i> My Courses</a></li>
                <li><a href="logout.php" class="btn btn-danger btn-sm"><i class="fas fa-sign-out-alt"></i> Logout</a></li>
            </ul>
        </div>
    </nav>

    <div class="container mt-4">
        <div class="card">
            <div class="card-header">
                <h1><i class="fas fa-chart-bar"></i> Quiz Results</h1>
                <p class="text-secondary">
                    Quiz: <strong><?php echo htmlspecialchars($attempt['quiz_title']); ?></strong> |
                    Course: <strong><?php echo htmlspecialchars($attempt['course_title']); ?></strong>
                </p>
            </div>

            <!-- Result Summary -->
            <div class="p-4">
                <div class="row text-center mb-4">
                    <div class="col">
                        <div class="card <?php echo (isset($attempt['passed']) && $attempt['passed']) ? 'bg-success-light' : 'bg-danger-light'; ?>">
                            <h2 style="color: <?php echo (isset($attempt['passed']) && $attempt['passed']) ? '#10b981' : '#ef4444'; ?>;">
                                <?php echo isset($attempt['percentage']) ? number_format($attempt['percentage'], 1) : '0.0'; ?>%
                            </h2>
                            <p>Final Score</p>
                        </div>
                    </div>
                    <div class="col">
                        <div class="card">
                            <h2 style="color: #2563eb;"><?php echo isset($attempt['total_score']) ? $attempt['total_score'] : '0'; ?>/<?php echo isset($attempt['max_score']) ? $attempt['max_score'] : '5'; ?></h2>
                            <p>Points Earned</p>
                        </div>
                    </div>
                    <div class="col">
                        <div class="card">
                            <h2 style="color: #f59e0b;">
                                <?php echo isset($attempt['time_taken_seconds']) ? gmdate("H:i:s", $attempt['time_taken_seconds']) : '00:00:00'; ?>
                            </h2>
                            <?php echo gmdate("H:i:s", $attempt['time_taken_seconds']); ?>
                            </h2>
                            <p>Time Taken</p>
                        </div>
                    </div>
                    <div class="col">
                        <div class="card">
                            <h2>
                                <?php if (isset($attempt['passed']) && $attempt['passed']): ?>
                                    <span class="badge badge-success"><i class="fas fa-check-circle"></i> PASSED</span>
                                <?php else: ?>
                                    <span class="badge badge-danger"><i class="fas fa-times-circle"></i> FAILED</span>
                                <?php endif; ?>
                            </h2>
                            <p>Status</p>
                        </div>
                    </div>
                </div>

                <!-- Pass/Fail Message -->
                <div class="alert <?php echo (isset($attempt['passed']) && $attempt['passed']) ? 'alert-success' : 'alert-danger'; ?>">
                    <i class="fas <?php echo (isset($attempt['passed']) && $attempt['passed']) ? 'fa-check-circle' : 'fa-exclamation-circle'; ?>"></i>
                    <strong>
                        <?php if (isset($attempt['passed']) && $attempt['passed']): ?>
                            Congratulations! You passed the quiz.
                        <?php else: ?>
                            You need <?php echo isset($quiz['passing_score']) ? $quiz['passing_score'] : '70'; ?>% to pass.
                            You scored <?php echo isset($attempt['percentage']) ? number_format($attempt['percentage'], 1) : '0.0'; ?>%.
                            Try again!
                        <?php endif; ?>
                    </strong>
                </div>

                <!-- Detailed Results -->
                <h3 class="mt-4"><i class="fas fa-list-ol"></i> Question Review</h3>
                <?php foreach ($answers as $index => $answer): ?>
                    <div class="card mb-3 <?php echo $answer['is_correct'] ? 'border-success' : 'border-danger'; ?>">
                        <div class="card-header <?php echo $answer['is_correct'] ? 'bg-success-light' : 'bg-danger-light'; ?>">
                            <div class="flex-between">
                                <div>
                                    <strong>Question <?php echo $index + 1; ?></strong>
                                    (<?php echo $answer['points_earned']; ?>/<?php echo $answer['max_points']; ?> points)
                                </div>
                                <div>
                                    <?php if ($answer['is_correct']): ?>
                                        <span class="badge badge-success"><i class="fas fa-check"></i> Correct</span>
                                    <?php else: ?>
                                        <span class="badge badge-danger"><i class="fas fa-times"></i> Incorrect</span>
                                    <?php endif; ?>
                                </div>
                            </div>
                        </div>
                        <div class="p-3">
                            <p><strong><?php echo htmlspecialchars($answer['question_text']); ?></strong></p>

                            <div class="row">
                                <div class="col">
                                    <p class="mb-1"><strong>Your Answer:</strong></p>
                                    <p class="<?php echo $answer['is_correct'] ? 'text-success' : 'text-danger'; ?>">
                                        <i class="fas fa-user"></i>
                                        <?php echo htmlspecialchars($answer['selected_option'] ?? $answer['answer_text'] ?? 'No answer'); ?>
                                    </p>
                                </div>
                                <?php if (!$answer['is_correct'] && isset($answer['correct_option'])): ?>
                                    <div class="col">
                                        <p class="mb-1"><strong>Correct Answer:</strong></p>
                                        <p class="text-success">
                                            <i class="fas fa-check-circle"></i>
                                            <?php echo htmlspecialchars($answer['correct_option']); ?>
                                        </p>
                                    </div>
                                <?php endif; ?>
                            </div>
                        </div>
                    </div>
                <?php endforeach; ?>

                <!-- Action Buttons -->
                <div class="row mt-4">
                    <div class="col">
                        <?php if (!$attempt['passed']): ?>
                            <a href="take_quiz.php?quiz_id=<?php echo $attempt['quiz_id']; ?>"
                                class="btn btn-primary btn-block btn-lg">
                                <i class="fas fa-redo"></i> Retry Quiz
                            </a>
                        <?php endif; ?>
                    </div>
                    <div class="col">
                        <a href="my_courses.php" class="btn btn-secondary btn-block btn-lg">
                            <i class="fas fa-arrow-left"></i> Back to Courses
                        </a>
                    </div>
                    <div class="col">
                        <?php if ($attempt['passed']): ?>
                            <a href="certificates.php?course_id=<?php echo $attempt['course_id']; ?>"
                                class="btn btn-success btn-block btn-lg">
                                <i class="fas fa-certificate"></i> Get Certificate
                            </a>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <style>
        .bg-success-light {
            background-color: rgba(16, 185, 129, 0.1);
        }

        .bg-danger-light {
            background-color: rgba(239, 68, 68, 0.1);
        }

        .border-success {
            border: 2px solid #10b981;
        }

        .border-danger {
            border: 2px solid #ef4444;
        }
    </style>
</body>

</html>