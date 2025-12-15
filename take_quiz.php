<?php
// take_quiz.php - Student Quiz Taking Interface
session_start();

// Check if user is logged in as student
if (!isset($_SESSION['user_id'], $_SESSION['role']) || $_SESSION['role'] !== 'student') {
    header('Location: login.php');
    exit();
}

require_once 'db_conn.php';

$user_id = $_SESSION['user_id'];
$quiz_id = isset($_GET['quiz_id']) ? intval($_GET['quiz_id']) : 0;
$course_id = 0;
$quiz = null;
$questions = [];
$time_limit = 0;
$attempt_id = 0;

// Fetch quiz details
try {
    $stmt = $pdo->prepare("SELECT q.*, c.title as course_title, c.id as course_id 
                          FROM quizzes q 
                          JOIN courses c ON q.course_id = c.id 
                          WHERE q.id = ? AND q.is_active = TRUE");
    $stmt->execute([$quiz_id]);
    $quiz = $stmt->fetch();

    if ($quiz) {
        $course_id = $quiz['course_id'];
        $time_limit = $quiz['time_limit'] * 60; // Convert to seconds

        // Check if user is enrolled
        $stmt = $pdo->prepare("SELECT id FROM enrollments WHERE user_id = ? AND course_id = ?");
        $stmt->execute([$user_id, $course_id]);
        if (!$stmt->fetch()) {
            header('Location: student_dashboard.php?error=NotEnrolled');
            exit();
        }

        // Check if already passed
        $stmt = $pdo->prepare("SELECT passed FROM user_quiz_progress WHERE user_id = ? AND quiz_id = ?");
        $stmt->execute([$user_id, $quiz_id]);
        $progress = $stmt->fetch();
        if ($progress && $progress['passed']) {
            header('Location: quiz_results.php?quiz_id=' . $quiz_id);
            exit();
        }

        // Create new attempt
        $stmt = $pdo->prepare("INSERT INTO quiz_attempts (user_id, quiz_id, started_at) VALUES (?, ?, NOW())");
        $stmt->execute([$user_id, $quiz_id]);
        $attempt_id = $pdo->lastInsertId();

        // Fetch questions with options
        $stmt = $pdo->prepare("SELECT qq.* FROM quiz_questions qq WHERE qq.quiz_id = ? ORDER BY RAND()");
        $stmt->execute([$quiz_id]);
        $questions = $stmt->fetchAll();

        foreach ($questions as &$question) {
            $stmt = $pdo->prepare("SELECT * FROM quiz_options WHERE question_id = ? ORDER BY RAND()");
            $stmt->execute([$question['id']]);
            $question['options'] = $stmt->fetchAll();
        }
    }
} catch (PDOException $e) {
    error_log("Quiz loading error: " . $e->getMessage());
    header('Location: my_courses.php?error=QuizLoadFailed');
    exit();
}


?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Take Quiz - <?php echo htmlspecialchars($quiz['title']); ?></title>
    <link rel="stylesheet" href="style.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
</head>

<body>
    <!-- Navigation similar to other student pages -->
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
                <div class="flex-between">
                    <div>
                        <h1><i class="fas fa-question-circle"></i> <?php echo htmlspecialchars($quiz['title']); ?></h1>
                        <p class="text-secondary">
                            Course: <strong><?php echo htmlspecialchars($quiz['course_title']); ?></strong> |
                            Questions: <strong><?php echo count($questions); ?></strong> |
                            Passing Score: <strong><?php echo $quiz['passing_score']; ?>%</strong>
                        </p>
                    </div>
                    <div id="timer" class="badge badge-danger">
                        <i class="fas fa-clock"></i> Time: <span id="time-display"><?php echo gmdate("H:i:s", $time_limit); ?></span>
                    </div>
                </div>
            </div>

            <div class="alert alert-info">
                <i class="fas fa-info-circle"></i>
                <strong>Instructions:</strong>
                <ul class="mb-0 mt-2">
                    <li>Answer all questions before time runs out</li>
                    <li>You cannot go back once you submit</li>
                    <li>Passing score: <?php echo $quiz['passing_score']; ?>%</li>
                    <li>Timer will automatically submit when time is up</li>
                </ul>
            </div>

            <form id="quiz-form" method="POST" action="grade_quiz.php">
                <input type="hidden" name="attempt_id" value="<?php echo $attempt_id; ?>">
                <input type="hidden" name="quiz_id" value="<?php echo $quiz_id; ?>">

                <?php foreach ($questions as $index => $question): ?>
                    <div class="card mb-4 question-card">
                        <div class="card-header">
                            <h4>Question <?php echo $index + 1; ?> (<?php echo $question['points']; ?> points)</h4>
                        </div>
                        <div class="p-3">
                            <p class="mb-3"><strong><?php echo htmlspecialchars($question['question_text']); ?></strong></p>

                            <?php if ($question['question_type'] === 'multiple_choice'): ?>
                                <?php foreach ($question['options'] as $option): ?>
                                    <div class="form-check mb-2">
                                        <input class="form-check-input" type="radio"
                                            name="question_<?php echo $question['id']; ?>"
                                            id="option_<?php echo $option['id']; ?>"
                                            value="<?php echo $option['id']; ?>" required>
                                        <label class="form-check-label" for="option_<?php echo $option['id']; ?>">
                                            <?php echo htmlspecialchars($option['option_text']); ?>
                                        </label>
                                    </div>
                                <?php endforeach; ?>
                            <?php elseif ($question['question_type'] === 'true_false'): ?>
                                <div class="form-check mb-2">
                                    <input class="form-check-input" type="radio"
                                        name="question_<?php echo $question['id']; ?>"
                                        id="true_<?php echo $question['id']; ?>"
                                        value="true" required>
                                    <label class="form-check-label" for="true_<?php echo $question['id']; ?>">
                                        True
                                    </label>
                                </div>
                                <div class="form-check mb-2">
                                    <input class="form-check-input" type="radio"
                                        name="question_<?php echo $question['id']; ?>"
                                        id="false_<?php echo $question['id']; ?>"
                                        value="false" required>
                                    <label class="form-check-label" for="false_<?php echo $question['id']; ?>">
                                        False
                                    </label>
                                </div>
                            <?php endif; ?>
                        </div>
                    </div>
                <?php endforeach; ?>

                <div class="row mt-4">
                    <div class="col">
                        <a href="quiz_results.php?attempt_id=<?php echo $attempt_id; ?>"
                            class="btn btn-success btn-lg btn-block">
                            <i class="fas fa-paper-plane"></i> Submit Quiz
                        </a>
                    </div>
                    <div class="col">
                        <a href="my_courses.php" class="btn btn-danger btn-lg btn-block">
                            <i class="fas fa-times"></i> Cancel
                        </a>
                    </div>
                </div>
            </form>
        </div>
    </div>

    <script>
        // Timer functionality
        let timeLeft = <?php echo $time_limit; ?>;
        const timerElement = document.getElementById('time-display');
        const quizForm = document.getElementById('quiz-form');

        function updateTimer() {
            if (timeLeft <= 0) {
                quizForm.submit();
                return;
            }

            const hours = Math.floor(timeLeft / 3600);
            const minutes = Math.floor((timeLeft % 3600) / 60);
            const seconds = timeLeft % 60;

            timerElement.textContent =
                (hours > 0 ? hours.toString().padStart(2, '0') + ':' : '') +
                minutes.toString().padStart(2, '0') + ':' +
                seconds.toString().padStart(2, '0');

            // Change color when less than 5 minutes
            if (timeLeft < 300) {
                document.getElementById('timer').style.backgroundColor = '#ef4444';
            }

            timeLeft--;
        }

        setInterval(updateTimer, 1000);
        updateTimer();

        // Prevent accidental navigation
        // window.onbeforeunload = function() {
        //     return "Are you sure you want to leave? Your quiz progress will be lost.";
        // };
    </script>
</body>

</html>