<?php
// my_courses.php - My Courses Page
session_start();

// Check if user is logged in and is student
if (!isset($_SESSION['user_id'], $_SESSION['role']) || $_SESSION['role'] !== 'student') {
    header('Location: login.php');
    exit();
}

// Include database connection
require_once 'db_conn.php';

// Initialize session variables with safe defaults
$user_id = $_SESSION['user_id'] ?? 0;
$full_name = $_SESSION['full_name'] ?? 'Student';
$email = $_SESSION['email'] ?? '';

// Initialize variables
$enrolled_courses = [];
$error_message = '';

// Fetch enrolled courses with course details and quiz status
try {
    $stmt = $pdo->prepare("SELECT 
        c.id as course_id, 
        c.title, 
        c.description,
        c.thumbnail_image, 
        c.video_url, 
        c.created_at,
        u.full_name as instructor_name,
        e.enrollment_date,
        q.id as quiz_id,
        q.title as quiz_title,
        q.passing_score,
        up.passed as quiz_passed,
        up.best_score as quiz_score,
        up.last_attempt as quiz_last_attempt
        FROM enrollments e
        JOIN courses c ON e.course_id = c.id
        JOIN users u ON c.created_by = u.id
        LEFT JOIN quizzes q ON q.course_id = c.id AND q.is_active = TRUE
        LEFT JOIN user_quiz_progress up ON up.quiz_id = q.id AND up.user_id = ?
        WHERE e.user_id = ?
        ORDER BY e.enrollment_date DESC");
    
    $stmt->execute([$user_id, $user_id]);
    $enrolled_courses = $stmt->fetchAll();
    
    // Group courses (some might have multiple rows due to LEFT JOIN)
    $grouped_courses = [];
    foreach ($enrolled_courses as $course) {
        $course_id = $course['course_id'];
        
        if (!isset($grouped_courses[$course_id])) {
            $grouped_courses[$course_id] = [
                'course_id' => $course['course_id'],
                'title' => $course['title'],
                'description' => $course['description'],
                'thumbnail_image' => $course['thumbnail_image'],
                'video_url' => $course['video_url'],
                'created_at' => $course['created_at'],
                'instructor_name' => $course['instructor_name'],
                'enrollment_date' => $course['enrollment_date'],
                'has_quiz' => false,
                'quiz_info' => []
            ];
        }
        
        // If course has quiz
        if ($course['quiz_id']) {
            $grouped_courses[$course_id]['has_quiz'] = true;
            $grouped_courses[$course_id]['quiz_info'] = [
                'quiz_id' => $course['quiz_id'],
                'quiz_title' => $course['quiz_title'],
                'quiz_passed' => (bool)$course['quiz_passed'],
                'quiz_score' => $course['quiz_score'],
                'passing_score' => $course['passing_score'],
                'last_attempt' => $course['quiz_last_attempt']
            ];
        }
    }
    
    $enrolled_courses = array_values($grouped_courses);
    
} catch (PDOException $e) {
    error_log("Error fetching enrolled courses: " . $e->getMessage());
    $error_message = "Unable to load your courses. Please try again later.";
}

// Get total enrolled courses count
$total_enrolled = count($enrolled_courses);

// Calculate statistics
$courses_with_video = 0;
$courses_with_quiz = 0;
$quizzes_passed = 0;
$courses_this_month = 0;
$current_month = date('Y-m');

foreach ($enrolled_courses as $course) {
    // Count courses with videos
    if (!empty($course['video_url']) && trim($course['video_url']) !== '') {
        $courses_with_video++;
    }
    
    // Count courses with quizzes
    if ($course['has_quiz']) {
        $courses_with_quiz++;
    }
    
    // Count passed quizzes
    if ($course['has_quiz'] && $course['quiz_info']['quiz_passed']) {
        $quizzes_passed++;
    }
    
    // Count courses enrolled this month
    if (date('Y-m', strtotime($course['enrollment_date'])) == $current_month) {
        $courses_this_month++;
    }
}

// Handle quiz retake request
if (isset($_GET['retake_quiz']) && is_numeric($_GET['retake_quiz'])) {
    $quiz_id = intval($_GET['retake_quiz']);
    
    // Verify user has access to this quiz
    foreach ($enrolled_courses as $course) {
        if ($course['has_quiz'] && $course['quiz_info']['quiz_id'] == $quiz_id) {
            header('Location: take_quiz.php?quiz_id=' . $quiz_id);
            exit();
        }
    }
    
    // If quiz not found, show error
    $error_message = "Quiz not found or you don't have access to it.";
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>My Courses - E-Learning Platform</title>
    <link rel="stylesheet" href="style.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
</head>
<body>
    <!-- Navigation -->
    <nav class="navbar">
        <div class="container">
            <div class="logo">
                <i class="fas fa-graduation-cap"></i>
                <span>E-Learn Student</span>
            </div>
            <ul class="nav-links">
                <li><a href="student_dashboard.php" class="nav-link"><i class="fas fa-home"></i> Dashboard</a></li>
                <li><a href="my_courses.php" class="nav-link active"><i class="fas fa-book-open"></i> My Courses</a></li>
                <li><a href="certificates.php" class="nav-link"><i class="fas fa-certificate"></i> Certificates</a></li>
                <li><a href="profile.php" class="nav-link"><i class="fas fa-user-circle"></i> Profile</a></li>
                <li><a href="logout.php" class="btn btn-danger btn-sm"><i class="fas fa-sign-out-alt"></i> Logout</a></li>
                
            </ul>
        </div>
    </nav>

    <!-- Main Content -->
    <div class="container mt-4">
        <!-- Header -->
        <div class="card mb-4">
            <div class="flex-between">
                <div>
                    <h1>My Courses</h1>
                    <p class="text-secondary">View and manage all your enrolled courses</p>
                </div>
                <div>
                    <div class="badge badge-primary" style="font-size: 1rem; padding: 0.5rem 1rem;">
                        <i class="fas fa-bookmark"></i> <?php echo $total_enrolled; ?> Courses
                    </div>
                </div>
            </div>
            <div class="card mb-4">
   <!-- Add this after the header card in my_courses.php -->
<div class="card mb-4">
    <div class="card-body">
        <form method="GET" action="search.php" class="d-flex">
            <input type="text" name="q" class="form-control mr-2" placeholder="Search your courses..." 
                   value="<?php echo htmlspecialchars($_GET['q'] ?? ''); ?>">
            
            <?php
            // Get unique categories from enrolled courses
            try {
                $stmt = $pdo->prepare("SELECT DISTINCT c.category 
                                      FROM courses c
                                      JOIN enrollments e ON c.id = e.course_id
                                      WHERE e.user_id = ? AND c.category IS NOT NULL AND c.category != ''
                                      ORDER BY c.category");
                $stmt->execute([$user_id]);
                $categories = $stmt->fetchAll(PDO::FETCH_COLUMN, 0);
            } catch (PDOException $e) {
                $categories = [];
            }
            ?>
            
            <select name="category" class="form-control mr-2" style="max-width: 200px;">
                <option value="">All Categories</option>
                <?php foreach ($categories as $cat): ?>
                <option value="<?php echo htmlspecialchars($cat); ?>" 
                    <?php echo (isset($_GET['category']) && $_GET['category'] == $cat) ? 'selected' : ''; ?>>
                    <?php echo htmlspecialchars($cat); ?>
                </option>
                <?php endforeach; ?>
            </select>
            
            <select name="status" class="form-control mr-2" style="max-width: 150px;">
                <option value="">All Status</option>
                <option value="in_progress" <?php echo (isset($_GET['status']) && $_GET['status'] == 'in_progress') ? 'selected' : ''; ?>>In Progress</option>
                <option value="completed" <?php echo (isset($_GET['status']) && $_GET['status'] == 'completed') ? 'selected' : ''; ?>>Completed</option>
                <option value="not_started" <?php echo (isset($_GET['status']) && $_GET['status'] == 'not_started') ? 'selected' : ''; ?>>Not Started</option>
            </select>
            
            <button type="submit" class="btn btn-primary">
                <i class="fas fa-search"></i> Search
            </button>
            
            <?php if (isset($_GET['q']) || isset($_GET['category']) || isset($_GET['status'])): ?>
            <a href="my_courses.php" class="btn btn-secondary ml-2">
                <i class="fas fa-times"></i> Clear
            </a>
            <?php endif; ?>
        </form>
    </div>
</div>

            <!-- Display Error Message -->
            <?php if ($error_message): ?>
            <div class="alert alert-danger fade-in mb-4" id="error-message">
                <i class="fas fa-exclamation-circle"></i> <?php echo htmlspecialchars($error_message); ?>
                <button type="button" class="close-btn" onclick="this.parentElement.style.display='none'">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            <?php endif; ?>

            <!-- Empty State or Courses Grid -->
            <?php if (empty($enrolled_courses)): ?>
            <div class="card text-center p-5">
                <div style="font-size: 4rem; color: #d1d5db;">
                    <i class="fas fa-book-open"></i>
                </div>
                <h3 class="mt-3">No Courses Enrolled Yet</h3>
                <p class="text-secondary">You haven't enrolled in any courses yet.</p>
                <div class="mt-4">
                    <a href="student_dashboard.php" class="btn btn-primary">
                        <i class="fas fa-search"></i> Browse Available Courses
                    </a>
                </div>
            </div>
            <?php else: ?>
            
            <!-- Courses Grid -->
            <div class="course-grid">
                <?php foreach ($enrolled_courses as $course):
                    $has_video = !empty($course['video_url']) && trim($course['video_url']) !== '';
                    $has_quiz = $course['has_quiz'];
                    $quiz_passed = $has_quiz && $course['quiz_info']['quiz_passed'];
                    $quiz_score = $has_quiz ? $course['quiz_info']['quiz_score'] : null;
                    $quiz_id = $has_quiz ? $course['quiz_info']['quiz_id'] : null;
                    $passing_score = $has_quiz ? $course['quiz_info']['passing_score'] : null;
                ?>
                <div class="card course-card">
                    <!-- Course Thumbnail -->
                    <?php if (!empty($course['thumbnail_image']) && file_exists($course['thumbnail_image'])): ?>
                    <img src="<?php echo htmlspecialchars($course['thumbnail_image']); ?>"
                         alt="<?php echo htmlspecialchars($course['title']); ?>"
                         class="course-thumbnail">
                    <?php else: ?>
                    <div class="course-thumbnail" style="background: linear-gradient(135deg, #2563eb 0%, #3b82f6 100%);">
                        <div class="text-center" style="height: 100%; display: flex; align-items: center; justify-content: center;">
                            <i class="fas fa-book" style="font-size: 3rem; color: white;"></i>
                        </div>
                    </div>
                    <?php endif; ?>
                    
                    <div class="course-content">
                        <h4 class="course-title"><?php echo htmlspecialchars($course['title']); ?></h4>
                        <p class="course-description">
                            <?php
                            $description = htmlspecialchars($course['description']);
                            echo strlen($description) > 100 ? substr($description, 0, 100) . '...' : $description;
                            ?>
                        </p>

                        <div class="course-meta">
                            <div>
                                <small class="text-secondary">
                                    <i class="fas fa-user-tie"></i>
                                    <?php echo htmlspecialchars($course['instructor_name']); ?>
                                </small><br>
                                <small class="text-secondary">
                                    <i class="far fa-calendar"></i>
                                    Enrolled: <?php echo date('M d, Y', strtotime($course['enrollment_date'])); ?>
                                </small>
                                <?php if ($has_quiz): ?>
                                <br>
                                <small class="text-secondary">
                                    <i class="fas fa-question-circle"></i>
                                    <?php if ($quiz_passed): ?>
                                        Quiz: <span class="text-success"><?php echo $quiz_score; ?>% (Passed)</span>
                                    <?php else: ?>
                                        Quiz: <span class="text-warning"><?php echo $quiz_score ? $quiz_score . '%' : 'Not taken'; ?></span>
                                    <?php endif; ?>
                                </small>
                                <?php endif; ?>
                            </div>

                            <!-- Course Actions -->
                            <div class="course-actions">
                                <?php if ($has_quiz && !$quiz_passed): ?>
                                    <!-- Take/Retaike Quiz Button -->
                                    <a href="take_quiz.php?quiz_id=<?php echo $quiz_id; ?>" 
                                       class="btn btn-warning btn-sm mb-1">
                                        <i class="fas fa-question-circle"></i> 
                                        <?php echo $quiz_score ? 'Retake Quiz' : 'Take Quiz'; ?>
                                    </a>
                                    <br>
                                <?php elseif ($quiz_passed): ?>
                                    <!-- Quiz Results Button -->
                                    <a href="quiz_results.php?quiz_id=<?php echo $quiz_id; ?>" 
                                       class="btn btn-success btn-sm mb-1">
                                        <i class="fas fa-chart-bar"></i> View Results
                                    </a>
                                    <br>
                                <?php endif; ?>
                                
                                <?php if ($has_video): ?>
                                    <!-- Watch Video Button -->
                                    <a href="<?php echo htmlspecialchars($course['video_url']); ?>"
                                       target="_blank"
                                       rel="noopener noreferrer"
                                       class="btn btn-primary btn-sm">
                                        <i class="fas fa-play-circle"></i> Watch Video
                                    </a>
                                <?php else: ?>
                                    <!-- No Video Available -->
                                    <button class="btn btn-disabled btn-sm" disabled>
                                        <i class="far fa-clock"></i> Coming Soon
                                    </button>
                                <?php endif; ?>
                                
                                <?php if ($quiz_passed): ?>
                                    <!-- Certificate Button -->
                                    <a href="certificates.php?course_id=<?php echo $course['course_id']; ?>" 
                                       class="btn btn-info btn-sm mt-1">
                                        <i class="fas fa-certificate"></i> Get Certificate
                                    </a>
                                <?php endif; ?>
                            </div>
                        </div>
                    </div>
                </div>
                <?php endforeach; ?>
            </div>
            <?php endif; ?>

            <!-- Statistics -->
            <div class="row mt-4">
                <div class="col">
                    <div class="card text-center">
                        <h3 style="color: #2563eb;"><?php echo $total_enrolled; ?></h3>
                        <p class="text-secondary">Total Enrolled</p>
                        <i class="fas fa-graduation-cap" style="font-size: 2rem; color: #2563eb;"></i>
                    </div>
                </div>
                <div class="col">
                    <div class="card text-center">
                        <h3 style="color: #10b981;"><?php echo $courses_with_video; ?></h3>
                        <p class="text-secondary">Ready to Watch</p>
                        <i class="fas fa-play-circle" style="font-size: 2rem; color: #10b981;"></i>
                    </div>
                </div>
                <div class="col">
                    <div class="card text-center">
                        <h3 style="color: #f59e0b;"><?php echo $courses_this_month; ?></h3>
                        <p class="text-secondary">This Month</p>
                        <i class="fas fa-calendar-alt" style="font-size: 2rem; color: #f59e0b;"></i>
                    </div>
                </div>
                <div class="col">
                    <div class="card text-center">
                        <h3 style="color: #8b5cf6;"><?php echo $quizzes_passed; ?>/<?php echo $courses_with_quiz; ?></h3>
                        <p class="text-secondary">Quizzes Passed</p>
                        <i class="fas fa-check-circle" style="font-size: 2rem; color: #8b5cf6;"></i>
                    </div>
                </div>
            </div>

            <!-- Course Progress Summary -->
            <?php if ($total_enrolled > 0): ?>
            <div class="card mt-4">
                <div class="card-header">
                    <h3><i class="fas fa-chart-line text-primary"></i> Learning Progress</h3>
                </div>
                <div class="p-3">
                    <div class="progress-container">
                        <?php
                        $completed_courses = 0;
                        foreach ($enrolled_courses as $course) {
                            if ($course['has_quiz'] && $course['quiz_info']['quiz_passed']) {
                                $completed_courses++;
                            }
                        }
                        $completion_rate = $total_enrolled > 0 ? ($completed_courses / $total_enrolled) * 100 : 0;
                        ?>
                        <div class="progress-label">
                            <span>Course Completion</span>
                            <span><?php echo number_format($completion_rate, 1); ?>%</span>
                        </div>
                        <div class="progress">
                            <div class="progress-bar" style="width: <?php echo $completion_rate; ?>%"></div>
                        </div>
                        <small class="text-secondary"><?php echo $completed_courses; ?> of <?php echo $total_enrolled; ?> courses completed</small>
                    </div>
                    
                    <div class="progress-container mt-3">
                        <?php
                        $quiz_completion_rate = $courses_with_quiz > 0 ? ($quizzes_passed / $courses_with_quiz) * 100 : 0;
                        ?>
                        <div class="progress-label">
                            <span>Quiz Completion</span>
                            <span><?php echo number_format($quiz_completion_rate, 1); ?>%</span>
                        </div>
                        <div class="progress">
                            <div class="progress-bar" style="width: <?php echo $quiz_completion_rate; ?>%; background: linear-gradient(90deg, #10b981 0%, #34d399 100%);"></div>
                        </div>
                        <small class="text-secondary"><?php echo $quizzes_passed; ?> of <?php echo $courses_with_quiz; ?> quizzes passed</small>
                    </div>
                </div>
            </div>
            <?php endif; ?>

            <!-- Quick Actions -->
            <div class="card mt-4">
                <div class="card-header">
                    <h3><i class="fas fa-bolt"></i> Quick Actions</h3>
                </div>
                <div class="row mt-3">
                    <div class="col">
                        <a href="student_dashboard.php" class="btn btn-primary btn-block">
                            <i class="fas fa-search"></i> Browse All Courses
                        </a>
                    </div>
                    <div class="col">
                        <?php if ($quizzes_passed > 0): ?>
                        <a href="certificates.php" class="btn btn-success btn-block">
                            <i class="fas fa-certificate"></i> View Certificates (<?php echo $quizzes_passed; ?>)
                        </a>
                        <?php else: ?>
                        <button class="btn btn-disabled btn-block" disabled>
                            <i class="fas fa-certificate"></i> No Certificates Yet
                        </button>
                        <?php endif; ?>
                    </div>
                    <div class="col">
                        <?php
                        $pending_quizzes = 0;
                        foreach ($enrolled_courses as $course) {
                            if ($course['has_quiz'] && !$course['quiz_info']['quiz_passed']) {
                                $pending_quizzes++;
                            }
                        }
                        ?>
                        <?php if ($pending_quizzes > 0): ?>
                        <a href="#available-courses" class="btn btn-warning btn-block">
                            <i class="fas fa-question-circle"></i> Pending Quizzes (<?php echo $pending_quizzes; ?>)
                        </a>
                        <?php else: ?>
                        <button class="btn btn-disabled btn-block" disabled>
                            <i class="fas fa-check-circle"></i> All Quizzes Done
                        </button>
                        <?php endif; ?>
                    </div>
                    <div class="col">
                        <a href="logout.php" class="btn btn-danger btn-block">
                            <i class="fas fa-sign-out-alt"></i> Logout
                        </a>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Footer -->
    <footer class="footer mt-5">
        <div class="container">
            <div class="text-center">
                <p>&copy; <?php echo date('Y'); ?> E-Learning Platform. My Courses.</p>
                <p class="text-secondary">
                    <i class="fas fa-user-graduate"></i>
                    Student: <?php echo htmlspecialchars($full_name); ?>
                    | <?php echo htmlspecialchars($email); ?>
                </p>
            </div>
        </div>
    </footer>

    <!-- JavaScript -->
    <script>
    // Initialize when page is fully loaded
    function initMyCourses() {
        addCourseCardHover();
        autoHideAlerts();
        setupProgressBars();
    }

    // Add hover effects to course cards
    function addCourseCardHover() {
        var courseCards = document.querySelectorAll('.course-card');
        for (var i = 0; i < courseCards.length; i++) {
            courseCards[i].addEventListener('mouseenter', function() {
                this.style.transform = 'translateY(-5px)';
                this.style.boxShadow = '0 10px 20px rgba(0, 0, 0, 0.1)';
            });

            courseCards[i].addEventListener('mouseleave', function() {
                this.style.transform = 'translateY(0)';
                this.style.boxShadow = '';
            });
        }
    }

    // Auto-hide alert messages after 5 seconds
    function autoHideAlerts() {
        var alerts = document.querySelectorAll('.alert');
        for (var i = 0; i < alerts.length; i++) {
            var alertElement = alerts[i];
            setTimeout(function(alertEl) {
                return function() {
                    alertEl.style.opacity = '0';
                    setTimeout(function() {
                        alertEl.style.display = 'none';
                    }, 300);
                };
            }(alertElement), 5000);
        }
    }

    // Animate progress bars
    function setupProgressBars() {
        var progressBars = document.querySelectorAll('.progress-bar');
        progressBars.forEach(function(bar) {
            var width = bar.style.width;
            bar.style.width = '0%';
            
            setTimeout(function() {
                bar.style.transition = 'width 1.5s ease-in-out';
                bar.style.width = width;
            }, 300);
        });
    }

    // Initialize when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initMyCourses);
    } else {
        initMyCourses();
    }
    </script>

    <style>
    /* Custom disabled button style */
    .btn-disabled {
        background-color: #d1d5db !important;
        color: #6b7280 !important;
        border-color: #d1d5db !important;
        opacity: 0.7;
        cursor: not-allowed !important;
    }

    .btn-disabled:hover {
        transform: none !important;
        box-shadow: none !important;
    }

    /* Course Actions */
    .course-actions {
        display: flex;
        flex-direction: column;
        align-items: flex-end;
        gap: 0.25rem;
    }

    .course-actions .btn-sm {
        width: 100%;
        text-align: center;
        padding: 0.35rem 0.5rem;
        font-size: 0.8rem;
    }

    /* Watch video button */
    .btn-primary {
        background: linear-gradient(135deg, #2563eb 0%, #3b82f6 100%);
    }

    .btn-primary:hover {
        background: linear-gradient(135deg, #1d4ed8 0%, #2563eb 100%);
        transform: translateY(-2px);
        box-shadow: 0 4px 12px rgba(37, 99, 235, 0.3);
    }

    /* Take quiz button */
    .btn-warning {
        background: linear-gradient(135deg, #f59e0b 0%, #fbbf24 100%);
        color: white;
        border: none;
    }

    .btn-warning:hover {
        background: linear-gradient(135deg, #d97706 0%, #f59e0b 100%);
        transform: translateY(-2px);
        box-shadow: 0 4px 12px rgba(245, 158, 11, 0.3);
    }

    /* View results button */
    .btn-success {
        background: linear-gradient(135deg, #10b981 0%, #34d399 100%);
        color: white;
        border: none;
    }

    .btn-success:hover {
        background: linear-gradient(135deg, #059669 0%, #10b981 100%);
        transform: translateY(-2px);
        box-shadow: 0 4px 12px rgba(16, 185, 129, 0.3);
    }

    /* Certificate button */
    .btn-info {
        background: linear-gradient(135deg, #8b5cf6 0%, #a78bfa 100%);
        color: white;
        border: none;
    }

    .btn-info:hover {
        background: linear-gradient(135deg, #7c3aed 0%, #8b5cf6 100%);
        transform: translateY(-2px);
        box-shadow: 0 4px 12px rgba(139, 92, 246, 0.3);
    }

    /* Common button styles */
    .btn-sm {
        padding: 0.4rem 0.8rem;
        font-size: 0.85rem;
        border-radius: 6px;
        transition: all 0.2s ease;
    }

    .close-btn {
        background: none;
        border: none;
        color: inherit;
        cursor: pointer;
        padding: 0;
        margin-left: 1rem;
        float: right;
    }

    .close-btn:hover {
        opacity: 0.8;
    }

    .course-thumbnail {
        width: 100%;
        height: 180px;
        object-fit: cover;
        border-radius: var(--radius) var(--radius) 0 0;
    }

    /* Progress bars */
    .progress-container {
        margin-bottom: 1.5rem;
    }

    .progress-label {
        display: flex;
        justify-content: space-between;
        margin-bottom: 0.5rem;
        font-weight: 500;
    }

    .progress {
        height: 10px;
        background-color: #e5e7eb;
        border-radius: 5px;
        overflow: hidden;
        margin-bottom: 0.5rem;
    }

    .progress-bar {
        height: 100%;
        background: linear-gradient(90deg, #2563eb 0%, #3b82f6 100%);
        border-radius: 5px;
        transition: width 0.3s ease;
    }

    /* Badge styling */
    .badge-success {
        padding: 0.4rem 0.8rem;
        background-color: rgba(16, 185, 129, 0.1);
        color: #10b981;
        border: 1px solid rgba(16, 185, 129, 0.2);
        border-radius: 6px;
    }

    .badge-warning {
        padding: 0.4rem 0.8rem;
        background-color: rgba(245, 158, 11, 0.1);
        color: #f59e0b;
        border: 1px solid rgba(245, 158, 11, 0.2);
        border-radius: 6px;
    }

    /* Responsive grid */
    @media (max-width: 768px) {
        .course-grid {
            grid-template-columns: 1fr;
        }

        .row {
            flex-direction: column;
        }

        .col {
            margin-bottom: 1rem;
        }
        
        .course-actions {
            align-items: stretch;
            margin-top: 1rem;
        }
        
        .course-actions .btn-sm {
            width: 100%;
            margin-bottom: 0.25rem;
        }
    }
    </style>
</body>
</html>