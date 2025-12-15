<?php
// student_dashboard.php - Student Dashboard
session_start();

// Check if user is logged in and is student - redirect if not
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

// Initialize error/success messages
$error_message = '';
$success_message = '';
$enrolled_course_ids = [];
$all_courses = [];
$enrolled_courses = [];

// Fetch student's enrolled course IDs
try {
    $stmt = $pdo->prepare("SELECT course_id FROM enrollments WHERE user_id = ?");
    $stmt->execute([$user_id]);
    $enrolled_course_ids = $stmt->fetchAll(PDO::FETCH_COLUMN, 0);
    $enrolled_course_ids = $enrolled_course_ids ?: []; // Ensure array even if empty
} catch (PDOException $e) {
    error_log("Error fetching enrolled courses: " . $e->getMessage());
    $error_message = "Unable to load your enrolled courses.";
}

// Fetch ALL courses from database with instructor information
try {
    $stmt = $pdo->query("SELECT c.id as course_id, c.title, c.description, 
                        c.thumbnail_image, c.video_url, c.created_at, 
                        u.full_name as instructor_name,
                        c.has_quiz
                        FROM courses c 
                        JOIN users u ON c.created_by = u.id 
                        ORDER BY c.created_at DESC");
    $all_courses = $stmt->fetchAll();
} catch (PDOException $e) {
    error_log("Error fetching courses: " . $e->getMessage());
    $error_message = "Unable to load courses. Please try again later.";
}

// For enrolled courses, get quiz status
if (!empty($enrolled_course_ids) && !empty($all_courses)) {
    foreach ($all_courses as $course) {
        if (in_array($course['course_id'], $enrolled_course_ids)) {
            $enrolled_courses[] = $course;
        }
    }

    // Get quiz status for each enrolled course
    foreach ($enrolled_courses as &$course) {
        try {
            // REPLACE the quiz query with this:
            $stmt = $pdo->prepare("SELECT 
    q.id as quiz_id,
    q.title as quiz_title,
    up.passed as quiz_passed,
    up.best_score
    FROM quizzes q
    LEFT JOIN user_quiz_progress up ON q.id = up.quiz_id AND up.user_id = ?
    WHERE q.course_id = ? AND q.is_active = TRUE
    ORDER BY q.created_at DESC  -- Always get the NEWEST quiz
    LIMIT 1");
            $stmt->execute([$user_id, $course['course_id']]);
            $quiz_info = $stmt->fetch();

            if ($quiz_info) {
                $course['has_quiz'] = true;
                $course['quiz_id'] = $quiz_info['quiz_id']; // This is CRITICAL
                $course['quiz_title'] = $quiz_info['quiz_title'];
                $course['quiz_passed'] = (bool)$quiz_info['quiz_passed'];
                $course['quiz_score'] = $quiz_info['best_score'];
            } else {
                $course['has_quiz'] = false;
                $course['quiz_passed'] = false;
                $course['quiz_id'] = null; // Make sure this is set
            }
        } catch (PDOException $e) {
            $course['has_quiz'] = false;
            $course['quiz_passed'] = false;
            $course['quiz_id'] = null; // Make sure this is set
            error_log("Quiz status error: " . $e->getMessage());
        }
    }
    unset($course); // Unset reference
}

// Handle enrollment if requested via URL - with validation
if (isset($_GET['enroll']) && is_numeric($_GET['enroll'])) {
    $course_id_to_enroll = intval($_GET['enroll']);

    // Validate course exists
    $course_exists = false;
    foreach ($all_courses as $course) {
        if ($course['course_id'] == $course_id_to_enroll) {
            $course_exists = true;
            $course_title = $course['title'];
            break;
        }
    }

    if (!$course_exists) {
        $error_message = "Invalid course selected.";
    } elseif (in_array($course_id_to_enroll, $enrolled_course_ids)) {
        $error_message = "You are already enrolled in this course.";
    } else {
        // Check if course has video before allowing enrollment
        $has_video = false;
        foreach ($all_courses as $course) {
            if (
                $course['course_id'] == $course_id_to_enroll &&
                !empty($course['video_url']) &&
                trim($course['video_url']) !== ''
            ) {
                $has_video = true;
                break;
            }
        }

        if (!$has_video) {
            $error_message = "Cannot enroll in a course without video content.";
        } else {
            // Insert enrollment with proper error handling
            try {
                $stmt = $pdo->prepare("INSERT INTO enrollments (user_id, course_id, enrollment_date) 
                                      VALUES (?, ?, NOW())");
                if ($stmt->execute([$user_id, $course_id_to_enroll])) {
                    // Update local array and redirect
                    $enrolled_course_ids[] = $course_id_to_enroll;

                    // Add to enrolled courses array
                    foreach ($all_courses as $course) {
                        if ($course['course_id'] == $course_id_to_enroll) {
                            $course['enrollment_date'] = date('Y-m-d H:i:s');
                            $enrolled_courses[] = $course;
                            break;
                        }
                    }

                    header('Location: student_dashboard.php?msg=EnrolledSuccess');
                    exit();
                }
            } catch (PDOException $e) {
                error_log("Enrollment error: " . $e->getMessage());
                if (strpos($e->getMessage(), 'Duplicate entry') !== false) {
                    $error_message = "You are already enrolled in this course.";
                } else {
                    $error_message = "Failed to enroll. Please try again.";
                }
            }
        }
    }
}

// Check for success message from URL
if (isset($_GET['msg']) && $_GET['msg'] == 'EnrolledSuccess') {
    $success_message = "Successfully enrolled in the course!";
}
?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Student Dashboard - E-Learning Platform</title>
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
                <li><a href="student_dashboard.php" class="nav-link active"><i class="fas fa-home"></i> Dashboard</a></li>
                <li><a href="my_courses.php" class="nav-link"><i class="fas fa-book-open"></i> My Courses</a></li>
                <li><a href="certificates.php" class="nav-link"><i class="fas fa-certificate"></i> Certificates</a></li>
                <li><a href="profile.php" class="nav-link"><i class="fas fa-user-circle"></i> Profile</a></li>
                <li><a href="logout.php" class="btn btn-danger btn-sm"><i class="fas fa-sign-out-alt"></i> Logout</a></li>
            </ul>
        </div>
    </nav>

    <!-- Main Content -->
    <div class="container mt-4">
        <!-- Welcome Message -->
        <div class="card mb-4">
            <div class="flex-between">
                <div>
                    <h1>Welcome, <?php echo htmlspecialchars($full_name); ?>!</h1>
                    <p class="text-secondary">Continue your learning journey with us.</p>
                </div>
                <div>
                    <div class="badge badge-primary" style="font-size: 1rem; padding: 0.5rem 1rem;">
                        <i class="fas fa-bookmark"></i> Enrolled in <?php echo count($enrolled_course_ids); ?> courses
                    </div>
                </div>
            </div>
            <!-- Add this after the welcome message -->
<div class="card mb-4">
    <div class="card-body">
        <form method="GET" action="search.php" class="d-flex">
            <input type="text" name="q" class="form-control mr-2" placeholder="Search courses..." 
                   value="<?php echo htmlspecialchars($_GET['q'] ?? ''); ?>">
            
            <?php
            // Get unique categories from database
            try {
                $stmt = $pdo->query("SELECT DISTINCT category FROM courses WHERE category IS NOT NULL AND category != '' ORDER BY category");
                $categories = $stmt->fetchAll(PDO::FETCH_COLUMN, 0);
            } catch (PDOException $e) {
                $categories = ['Programming', 'Design', 'Business', 'Technology'];
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
            
            <select name="price" class="form-control mr-2" style="max-width: 150px;">
                <option value="">All Prices</option>
                <option value="free" <?php echo (isset($_GET['price']) && $_GET['price'] == 'free') ? 'selected' : ''; ?>>Free</option>
                <option value="paid" <?php echo (isset($_GET['price']) && $_GET['price'] == 'paid') ? 'selected' : ''; ?>>Paid</option>
            </select>
            
            <button type="submit" class="btn btn-primary">
                <i class="fas fa-search"></i> Search
            </button>
            
            <?php if (isset($_GET['q']) || isset($_GET['category']) || isset($_GET['price'])): ?>
            <a href="student_dashboard.php" class="btn btn-secondary ml-2">
                <i class="fas fa-times"></i> Clear
            </a>
            <?php endif; ?>
        </form>
    </div>
</div>

            <!-- Display Messages -->
            <?php if ($success_message): ?>
                <div class="alert alert-success fade-in mb-4" id="success-message">
                    <i class="fas fa-check-circle"></i> <?php echo htmlspecialchars($success_message); ?>
                    <button type="button" class="close-btn" onclick="this.parentElement.style.display='none'">
                        <i class="fas fa-times"></i>
                    </button>
                </div>
            <?php endif; ?>
            <?php if ($error_message): ?>
                <div class="alert alert-danger fade-in mb-4" id="error-message">
                    <i class="fas fa-exclamation-circle"></i> <?php echo htmlspecialchars($error_message); ?>
                    <button type="button" class="close-btn" onclick="this.parentElement.style.display='none'">
                        <i class="fas fa-times"></i>
                    </button>
                </div>
            <?php endif; ?>
        </div>

        <!-- My Enrolled Courses -->
        <?php if (!empty($enrolled_courses)): ?>
            <div class="card mb-4">
                <div class="card-header">
                    <h3><i class="fas fa-bookmark text-primary"></i> My Enrolled Courses</h3>
                    <a href="my_courses.php" class="btn btn-outline btn-sm">View All</a>
                </div>
                <div class="course-grid">
                    <?php foreach ($enrolled_courses as $course):
                        // SAFELY get all variables
                        $has_video = !empty($course['video_url']) && trim($course['video_url']) !== '';
                        $has_quiz = isset($course['has_quiz']) && $course['has_quiz'];
                        $quiz_passed = isset($course['quiz_passed']) && $course['quiz_passed'];
                        $quiz_id = isset($course['quiz_id']) ? $course['quiz_id'] : null;
                        $quiz_score = isset($course['quiz_score']) ? $course['quiz_score'] : null;
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
                                        </small>
                                        <?php if ($has_quiz): ?>
                                            <br>
                                            <small class="text-secondary">
                                                <i class="fas fa-question-circle"></i>
                                                <?php if ($quiz_passed): ?>
                                                    <span class="text-success">Quiz: <?php echo $quiz_score ? $quiz_score . '%' : 'Passed'; ?></span>
                                                <?php else: ?>
                                                    <span class="text-warning">Quiz Available</span>
                                                    <?php if ($quiz_id): ?>
                                                        <small class="text-info">(ID: <?php echo $quiz_id; ?>)</small>
                                                    <?php endif; ?>
                                                <?php endif; ?>
                                            </small>
                                        <?php endif; ?>
                                    </div>

                                    <!-- Button Logic for Enrolled Courses -->
                                    <div>
                                        <?php if ($has_quiz && !$quiz_passed && $quiz_id): ?>
                                            <!-- Take Quiz Button - FIXED -->
                                            <a href="take_quiz.php?quiz_id=<?php echo $quiz_id; ?>"
                                                class="btn btn-warning btn-sm take-quiz-btn"
                                                data-quiz-id="<?php echo $quiz_id; ?>">
                                                <i class="fas fa-question-circle"></i> Take Quiz
                                            </a>
                                        <?php elseif ($quiz_passed): ?>
                                            <!-- Quiz Passed Badge -->
                                            <span class="badge badge-success">
                                                <i class="fas fa-check-circle"></i> Quiz Passed
                                            </span>
                                        <?php elseif ($has_video): ?>
                                            <!-- Watch Video Button -->
                                            <a href="<?php echo htmlspecialchars($course['video_url']); ?>"
                                                target="_blank"
                                                rel="noopener noreferrer"
                                                class="btn btn-success btn-sm">
                                                <i class="fas fa-play-circle"></i> Watch Video
                                            </a>
                                        <?php else: ?>
                                            <!-- No Video Available -->
                                            <button class="btn btn-disabled btn-sm" disabled>
                                                <i class="far fa-clock"></i> Coming Soon
                                            </button>
                                        <?php endif; ?>
                                    </div>
                                </div>
                            </div>
                        </div>
                    <?php endforeach; ?>
                </div>
            </div>
        <?php endif; ?>

        <!-- All Available Courses -->
        <div class="card mb-4" id="available-courses">
            <div class="card-header">
                <h3><i class="fas fa-layer-group text-success"></i> All Available Courses</h3>
                <small class="text-secondary"><?php echo count($all_courses); ?> courses available</small>
            </div>

            <?php if (!empty($all_courses)): ?>
                <div class="course-grid">
                    <?php foreach ($all_courses as $course):
                        $is_enrolled = in_array($course['course_id'], $enrolled_course_ids);
                        $has_video = !empty($course['video_url']) && trim($course['video_url']) !== '';
                        $has_quiz = isset($course['has_quiz']) && $course['has_quiz'];
                    ?>
                        <div class="card course-card">
                            <!-- Course Thumbnail -->
                            <?php if (!empty($course['thumbnail_image']) && file_exists($course['thumbnail_image'])): ?>
                                <img src="<?php echo htmlspecialchars($course['thumbnail_image']); ?>"
                                    alt="<?php echo htmlspecialchars($course['title']); ?>"
                                    class="course-thumbnail">
                            <?php else: ?>
                                <div class="course-thumbnail" style="background: linear-gradient(135deg, #10b981 0%, #34d399 100%);">
                                    <div class="text-center" style="height: 100%; display: flex; align-items: center; justify-content: center;">
                                        <i class="fas fa-video" style="font-size: 3rem; color: white;"></i>
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
                                            <i class="far fa-clock"></i>
                                            Added: <?php echo date('M d, Y', strtotime($course['created_at'])); ?>
                                        </small>
                                        <?php if ($has_quiz): ?>
                                            <br>
                                            <small class="text-secondary">
                                                <i class="fas fa-question-circle"></i> Has Quiz
                                            </small>
                                        <?php endif; ?>
                                    </div>

                                    <!-- Advanced Button Logic -->
                                    <?php if ($is_enrolled): ?>
                                        <!-- Already enrolled -->
                                        <span class="badge badge-success">
                                            <i class="fas fa-check-circle"></i> Enrolled
                                        </span>
                                   <?php elseif (!$has_video): ?>
    <!-- Condition 1: No Video = Gray "Coming Soon" button -->
    <button class="btn btn-disabled btn-sm" disabled>
        <i class="far fa-clock"></i> Coming Soon
    </button>
<?php else: ?>
    <!-- Condition 3: Not Enrolled + Has Video = Check price -->
    <?php
    $course_price = isset($course['price']) ? floatval($course['price']) : 0;
    $is_free = $course_price == 0;
    ?>
    
    <?php if ($is_free): ?>
        <!-- Free Course -->
        <a href="student_dashboard.php?enroll=<?php echo $course['course_id']; ?>"
           class="btn btn-primary btn-sm enroll-btn"
           onclick="return confirm('Enroll in free course: \"<?php echo addslashes(htmlspecialchars($course['title'])); ?>\"?')">
            <i class="fas fa-plus-circle"></i> Enroll Free
        </a>
    <?php else: ?>
        <!-- Paid Course -->
        <a href="payment.php?course_id=<?php echo $course['course_id']; ?>"
           class="btn btn-success btn-sm enroll-btn">
            <i class="fas fa-shopping-cart"></i> Buy - $<?php echo number_format($course_price, 2); ?>
        </a>
    <?php endif; ?>
<?php endif; ?>
                                </div>
                            </div>
                        </div>
                    <?php endforeach; ?>
                </div>
            <?php else: ?>
                <!-- Empty State -->
                <div class="text-center p-5">
                    <div style="font-size: 4rem; color: #d1d5db;">
                        <i class="fas fa-book-open"></i>
                    </div>
                    <h3 class="mt-3">No Courses Available Yet</h3>
                    <p class="text-secondary">Check back later for new courses.</p>
                </div>
            <?php endif; ?>
        </div>

        <!-- Statistics -->
        <div class="row">
            <div class="col">
                <div class="card text-center">
                    <h3 style="color: #2563eb;"><?php echo count($all_courses); ?></h3>
                    <p class="text-secondary">Total Courses</p>
                    <i class="fas fa-book" style="font-size: 2rem; color: #2563eb;"></i>
                </div>
            </div>
            <div class="col">
                <div class="card text-center">
                    <h3 style="color: #10b981;"><?php echo count($enrolled_course_ids); ?></h3>
                    <p class="text-secondary">Enrolled Courses</p>
                    <i class="fas fa-bookmark" style="font-size: 2rem; color: #10b981;"></i>
                </div>
            </div>
            <div class="col">
                <div class="card text-center">
                    <?php
                    // Count passed quizzes
                    $passed_quizzes = 0;
                    foreach ($enrolled_courses as $course) {
                        if (isset($course['quiz_passed']) && $course['quiz_passed']) {
                            $passed_quizzes++;
                        }
                    }
                    ?>
                    <h3 style="color: #8b5cf6;"><?php echo $passed_quizzes; ?></h3>
                    <p class="text-secondary">Quizzes Passed</p>
                    <i class="fas fa-check-circle" style="font-size: 2rem; color: #8b5cf6;"></i>
                </div>
            </div>
            <div class="col">
                <div class="card text-center">
                    <a href="logout.php" class="btn btn-danger">
                        <i class="fas fa-sign-out-alt"></i> Logout
                    </a>
                    <p class="text-secondary mt-2">Secure sign out</p>
                </div>
            </div>
        </div>
    </div>

    <!-- Footer -->
    <footer class="footer mt-5">
        <div class="container">
            <div class="text-center">
                <p>&copy; <?php echo date('Y'); ?> E-Learning Platform. Student Dashboard.</p>
                <p class="text-secondary">
                    <i class="fas fa-user-graduate"></i>
                    Student: <?php echo htmlspecialchars($full_name); ?>
                    | <?php echo htmlspecialchars($email); ?>
                </p>
            </div>
        </div>
    </footer>

    <!-- VS Code Friendly JavaScript -->
     /* eslint-disable */
    <script>
        /**
         * Student Dashboard JavaScript
         * VS Code friendly version with proper error handling
         */

        (function() {
            'use strict';

            // Cache DOM elements
            let elementsCache = {};

            /**
             * Initialize all dashboard functionality
             */
            function initDashboard() {
                try {
                    cacheElements();
                    addCourseCardHover();
                    autoHideAlerts();
                    handleEnrollButtons();
                    handleTakeQuizButtons();
                    console.log('Dashboard initialized successfully');
                } catch (error) {
                    console.error('Error initializing dashboard:', error);
                }
            }

            /**
             * Cache frequently used DOM elements
             */
            function cacheElements() {
                elementsCache = {
                    courseCards: document.querySelectorAll('.course-card'),
                    alerts: document.querySelectorAll('.alert'),
                    enrollButtons: document.querySelectorAll('.enroll-btn'),
                    takeQuizButtons: document.querySelectorAll('.take-quiz-btn')
                };
            }

            /**
             * Add hover effects to course cards
             */
            function addCourseCardHover() {
                if (!elementsCache.courseCards || elementsCache.courseCards.length === 0) {
                    return;
                }

                elementsCache.courseCards.forEach(function(card) {
                    if (!card) return;

                    card.addEventListener('mouseenter', function() {
                        this.style.transform = 'translateY(-5px)';
                        this.style.boxShadow = '0 10px 20px rgba(0, 0, 0, 0.1)';
                    });

                    card.addEventListener('mouseleave', function() {
                        this.style.transform = 'translateY(0)';
                        this.style.boxShadow = '';
                    });
                });
            }

            /**
             * Auto-hide alert messages after 5 seconds
             */
            function autoHideAlerts() {
                if (!elementsCache.alerts || elementsCache.alerts.length === 0) {
                    return;
                }

                elementsCache.alerts.forEach(function(alertElement) {
                    if (!alertElement) return;

                    setTimeout(function() {
                        if (alertElement && alertElement.style) {
                            alertElement.style.opacity = '0';

                            setTimeout(function() {
                                if (alertElement && alertElement.style) {
                                    alertElement.style.display = 'none';
                                }
                            }, 300);
                        }
                    }, 5000);
                });
            }

            /**
             * Handle enroll button loading states
             */
            function handleEnrollButtons() {
                if (!elementsCache.enrollButtons || elementsCache.enrollButtons.length === 0) {
                    return;
                }

                elementsCache.enrollButtons.forEach(function(button) {
                    if (!button) return;

                    button.addEventListener('click', function(event) {
                        // Prevent multiple clicks
                        if (this.classList.contains('disabled')) {
                            event.preventDefault();
                            return false;
                        }

                        const originalHTML = this.innerHTML;
                        const buttonReference = this;

                        this.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Enrolling...';
                        this.classList.add('disabled');

                        // Reset after 3 seconds if still on page
                        setTimeout(function() {
                            if (buttonReference && buttonReference.innerHTML.includes('fa-spinner')) {
                                buttonReference.innerHTML = originalHTML;
                                buttonReference.classList.remove('disabled');
                            }
                        }, 3000);

                        return true;
                    });
                });
            }

            /**
             * Handle take quiz button loading states
             */
            function handleTakeQuizButtons() {
                if (!elementsCache.takeQuizButtons || elementsCache.takeQuizButtons.length === 0) {
                    return;
                }

                elementsCache.takeQuizButtons.forEach(function(button) {
                    if (!button) return;

                    button.addEventListener('click', function(event) {
                        // Get quiz ID from data attribute
                        const quizId = this.getAttribute('data-quiz-id');

                        if (!quizId || quizId === 'null' || quizId === '0') {
                            event.preventDefault();
                            alert('Error: Quiz ID is not valid. Please contact support.');
                            console.error('Invalid quiz ID:', quizId);
                            return false;
                        }

                        // Show loading state
                        const originalHTML = this.innerHTML;
                        const buttonReference = this;

                        this.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Loading Quiz...';
                        this.classList.add('disabled');

                        // Reset after 2 seconds if navigation fails
                        setTimeout(function() {
                            if (buttonReference && buttonReference.innerHTML.includes('fa-spinner')) {
                                buttonReference.innerHTML = originalHTML;
                                buttonReference.classList.remove('disabled');
                            }
                        }, 2000);

                        console.log('Navigating to quiz ID:', quizId);
                        return true;
                    });
                });
            }

            /**
             * DOM Ready Handler
             */
            function domReadyHandler() {
                // If DOM is already loaded, initialize immediately
                if (document.readyState === 'complete' ||
                    (document.readyState !== 'loading' && !document.documentElement.doScroll)) {
                    initDashboard();
                } else {
                    // Wait for DOM to be ready
                    document.addEventListener('DOMContentLoaded', initDashboard);
                }
            }

            // Start initialization
            domReadyHandler();

        })();
    </script>
/* eslint-disable */
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

        /* Enrollment button styling */
        .enroll-btn {
            background: linear-gradient(135deg, #2563eb 0%, #3b82f6 100%);
            color: white;
            border: none;
        }

        .enroll-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(37, 99, 235, 0.3);
            background: linear-gradient(135deg, #1d4ed8 0%, #2563eb 100%);
        }

        /* Take quiz button */
        .take-quiz-btn {
            background: linear-gradient(135deg, #f59e0b 0%, #fbbf24 100%);
            color: white;
            border: none;
        }

        .take-quiz-btn:hover {
            background: linear-gradient(135deg, #d97706 0%, #f59e0b 100%);
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(245, 158, 11, 0.3);
        }

        /* Watch video button */
        .btn-success {
            background: linear-gradient(135deg, #10b981 0%, #34d399 100%);
        }

        .btn-success:hover {
            background: linear-gradient(135deg, #059669 0%, #10b981 100%);
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(16, 185, 129, 0.3);
        }

        /* Common button styles */
        .btn-sm {
            padding: 0.4rem 0.8rem;
            font-size: 0.85rem;
            border-radius: 6px;
            transition: all 0.2s ease;
        }

        .disabled {
            opacity: 0.6;
            cursor: not-allowed !important;
            pointer-events: none;
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

        /* Badge styling */
        .badge-success {
            padding: 0.4rem 0.8rem;
            background-color: rgba(16, 185, 129, 0.1);
            color: #10b981;
            border: 1px solid rgba(16, 185, 129, 0.2);
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
        }
    </style>
</body>

</html>