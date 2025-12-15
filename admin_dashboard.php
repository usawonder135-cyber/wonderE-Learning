<?php
// admin_dashboard.php - Admin Dashboard
session_start();

// Check if user is logged in and is admin
if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'admin') {
    header('Location: login.php');
    exit();
}

// Include database connection
require_once 'db_conn.php';

// Check for success message from URL parameter
$success_message = '';
if (isset($_GET['msg'])) {
    switch ($_GET['msg']) {
        case 'CourseAdded':
            $success_message = "Course added successfully!";
            break;
        case 'CourseUpdated':
            $success_message = "Course updated successfully!";
            break;
        case 'CourseDeleted':
            $success_message = "Course deleted successfully!";
            break;
        case 'StudentAdded':
            $success_message = "Student added successfully!";
            break;
    }
}

// Fetch admin statistics
try {
    // Total students
    $stmt = $pdo->query("SELECT COUNT(*) as total_students FROM users WHERE role = 'student'");
    $total_students = $stmt->fetch()['total_students'];
    
    // Total courses
    $stmt = $pdo->query("SELECT COUNT(*) as total_courses FROM courses");
    $total_courses = $stmt->fetch()['total_courses'];
    
    // Total enrollments
    $stmt = $pdo->query("SELECT COUNT(*) as total_enrollments FROM enrollments");
    $total_enrollments = $stmt->fetch()['total_enrollments'];
    
    // Recent courses
    $stmt = $pdo->query("SELECT c.*, u.full_name as creator FROM courses c 
                        JOIN users u ON c.created_by = u.id 
                        ORDER BY c.created_at DESC LIMIT 5");
    $recent_courses = $stmt->fetchAll();
    
    // Recent enrollments with student info
    $stmt = $pdo->query("SELECT e.*, u.full_name as student_name, c.title as course_title 
                        FROM enrollments e 
                        JOIN users u ON e.user_id = u.id 
                        JOIN courses c ON e.course_id = c.id 
                        ORDER BY e.enrollment_date DESC LIMIT 5");
    $recent_enrollments = $stmt->fetchAll();
} catch (PDOException $e) {
    $error = "Failed to fetch dashboard data.";
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Dashboard - E-Learning Platform</title>
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
                <li><a href="admin_dashboard.php" class="nav-link active"><i class="fas fa-tachometer-alt"></i> Dashboard</a></li>
                <li><a href="#manage_courses" class="nav-link"><i class="fas fa-book"></i> Manage Courses</a></li>
                <li><a href="#students" class="nav-link"><i class="fas fa-users"></i> Students</a></li>
                <li><a href="#" onclick="alert('Report generation feature is coming in Version 2.0!')" class="nav-link"><i class="fas fa-chart-bar"></i> Reports</a></li>
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
                    <h1>Welcome, Admin <?php echo htmlspecialchars($_SESSION['full_name']); ?>!</h1>
                    <p class="text-secondary">Manage your e-learning platform efficiently.</p>
                </div>
                <div>
                    <a href="add_course.php" class="btn btn-primary">
                        <i class="fas fa-plus-circle"></i> Add New Course
                    </a>
                </div>
            </div>
        </div>

        <!-- Display Success Message -->
        <?php if ($success_message): ?>
            <div class="alert alert-success fade-in">
                <i class="fas fa-check-circle"></i> <?php echo $success_message; ?>
                <button type="button" class="close-btn" style="float: right; background: none; border: none; color: inherit; cursor: pointer;" onclick="this.parentElement.style.display='none'">
                    <i class="fas fa-times"></i>
                </button>
            </div>
        <?php endif; ?>

        <!-- Statistics Cards -->
        <div class="dashboard-grid">
            <div class="card">
                <div class="card-header">
                    <h3><i class="fas fa-users text-primary"></i> Total Students</h3>
                </div>
                <div class="text-center">
                    <h1 style="font-size: 3rem; color: #2563eb;"><?php echo $total_students ?? 0; ?></h1>
                    <p class="text-secondary">Registered Students</p>
                </div>
            </div>

            <div class="card">
                <div class="card-header">
                    <h3><i class="fas fa-book text-success"></i> Total Courses</h3>
                </div>
                <div class="text-center">
                    <h1 style="font-size: 3rem; color: #10b981;"><?php echo $total_courses ?? 0; ?></h1>
                    <p class="text-secondary">Available Courses</p>
                </div>
            </div>

            <div class="card">
                <div class="card-header">
                    <h3><i class="fas fa-chart-line text-warning"></i> Total Enrollments</h3>
                </div>
                <div class="text-center">
                    <h1 style="font-size: 3rem; color: #f59e0b;"><?php echo $total_enrollments ?? 0; ?></h1>
                    <p class="text-secondary">Course Enrollments</p>
                </div>
            </div>
            
            <div class="card">
                <div class="card-header">
                    <h3><i class="fas fa-user-plus text-danger"></i> New Today</h3>
                </div>
                <div class="text-center">
                    <h1 style="font-size: 3rem; color: #ef4444;">0</h1>
                    <p class="text-secondary">New Registrations</p>
                </div>
            </div>
        </div>

        <!-- Recent Courses & Enrollments -->
        <div class="row mt-4" id="manage_courses">
            <div class="col">
                <div class="card">
                    <div class="card-header">
                        <h3><i class="fas fa-clock"></i> Recently Added Courses</h3>
                        <a href="#manage_courses" class="btn btn-outline btn-sm">View All</a>
                    </div>
                    <div class="table-responsive">
                        <table class="table">
    <thead>
        <tr>
            <th>ID</th>
            <th>Title</th>
            <th>Instructor</th>
            <th>Date Added</th>
            <th>Quiz</th>
            <th>Actions</th>
        </tr>
    </thead>
    <tbody>
        <?php if (!empty($recent_courses)): ?>
            <?php foreach ($recent_courses as $course): 
                // Check if course has quiz
                $has_quiz = $course['has_quiz'] ?? false;
            ?>
                <tr>
                    <td>#<?php echo $course['id']; ?></td>
                    <td>
                        <strong><?php echo htmlspecialchars($course['title']); ?></strong>
                        <br>
                        <small class="text-secondary"><?php echo substr(htmlspecialchars($course['description']), 0, 30) . '...'; ?></small>
                    </td>
                    <td><?php echo htmlspecialchars($course['creator']); ?></td>
                    <td><?php echo date('M d, Y', strtotime($course['created_at'])); ?></td>
                    <td>
                        <?php if ($has_quiz): ?>
                            <span class="badge badge-success">
                                <i class="fas fa-check-circle"></i> Has Quiz
                            </span>
                        <?php else: ?>
                            <span class="badge badge-secondary">
                                <i class="fas fa-times-circle"></i> No Quiz
                            </span>
                        <?php endif; ?>
                    </td>
                    <td>
                        <div class="btn-group">
                            <a href="edit_course.php?id=<?php echo $course['id']; ?>" class="btn btn-sm btn-secondary" title="Edit">
                                <i class="fas fa-edit"></i>
                            </a>
                            <?php if (!$has_quiz): ?>
                                <a href="add_quiz.php?course_id=<?php echo $course['id']; ?>" class="btn btn-sm btn-success" title="Add Quiz">
                                    <i class="fas fa-question-circle"></i>
                                </a>
                            <?php else: ?>
                                <a href="manage_quiz.php?course_id=<?php echo $course['id']; ?>" class="btn btn-sm btn-info" title="Manage Quiz">
                                    <i class="fas fa-cog"></i>
                                </a>
                            <?php endif; ?>
                            <a href="delete_course.php?id=<?php echo $course['id']; ?>" 
                               class="btn btn-sm btn-danger" 
                               title="Delete"
                               onclick="return confirm('Are you sure you want to delete this course?')">
                                <i class="fas fa-trash"></i>
                            </a>
                        </div>
                    </td>
                </tr>
            <?php endforeach; ?>
                                <?php else: ?>
                                    <tr>
                                        <td colspan="5" class="text-center">No courses found. <a href="add_course.php">Add your first course</a></td>
                                    </tr>
                                <?php endif; ?>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
            
            <div class="col" id="students">
                <div class="card">
                    <div class="card-header">
                        <h3><i class="fas fa-user-graduate"></i> Recent Enrollments</h3>
                        <a href="#" class="btn btn-outline btn-sm">View All</a>
                    </div>
                    <div class="table-responsive">
                        <table class="table">
                            <thead>
                                <tr>
                                    <th>Student</th>
                                    <th>Course</th>
                                    <th>Date Enrolled</th>
                                    <th>Status</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php if (!empty($recent_enrollments)): ?>
                                    <?php foreach ($recent_enrollments as $enrollment): ?>
                                        <tr>
                                            <td><?php echo htmlspecialchars($enrollment['student_name']); ?></td>
                                            <td><?php echo htmlspecialchars($enrollment['course_title']); ?></td>
                                            <td><?php echo date('M d, Y', strtotime($enrollment['enrollment_date'])); ?></td>
                                            <td>
                                                <span class="badge badge-success">Active</span>
                                            </td>
                                        </tr>
                                    <?php endforeach; ?>
                                <?php else: ?>
                                    <tr>
                                        <td colspan="4" class="text-center">No enrollments yet.</td>
                                    </tr>
                                <?php endif; ?>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>

        <!-- Quick Actions -->
        <div class="card mt-4">
            <div class="card-header">
                <h3><i class="fas fa-bolt"></i> Quick Actions</h3>
            </div>
            <div class="row mt-3">
                <div class="col">
                    <a href="add_course.php" class="btn btn-primary btn-block">
                        <i class="fas fa-plus-circle"></i> Add New Course
                    </a>
                </div>
                <div class="col">
                    <a href="#" onclick="alert('Please ask students to register via the Signup page.')" class="btn btn-success btn-block">
                        <i class="fas fa-user-plus"></i> Add New Student
                    </a>
                </div>
                <div class="col">
                    <a href="#" onclick="alert('Report generation feature is coming in Version 2.0!')" class="btn btn-warning btn-block">
                        <i class="fas fa-file-export"></i> Generate Report
                    </a>
                </div>
                <div class="col">
                    <a href="logout.php" class="btn btn-danger btn-block">
                        <i class="fas fa-sign-out-alt"></i> Logout
                    </a>
                </div>
            </div>
        </div>
        
        <!-- System Information -->
        <div class="card mt-4">
            <div class="card-header">
                <h3><i class="fas fa-info-circle"></i> System Information</h3>
            </div>
            <div class="row">
                <div class="col">
                    <div class="p-3">
                        <h5><i class="fas fa-database"></i> Database Status</h5>
                        <p class="text-secondary">
                            <span class="badge badge-success">Connected</span> 
                            Database: elearning_db
                        </p>
                    </div>
                </div>
                <div class="col">
                    <div class="p-3">
                        <h5><i class="fas fa-server"></i> Server Info</h5>
                        <p class="text-secondary">
                            PHP Version: <?php echo phpversion(); ?><br>
                            Server Time: <?php echo date('Y-m-d H:i:s'); ?>
                        </p>
                    </div>
                </div>
                <div class="col">
                    <div class="p-3">
                        <h5><i class="fas fa-user-shield"></i> Admin Session</h5>
                        <p class="text-secondary">
                            Logged in since: <?php echo date('g:i A', $_SESSION['login_time'] ?? time()); ?><br>
                            Session ID: <?php echo substr(session_id(), 0, 10) . '...'; ?>
                        </p>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Footer -->
    <footer class="footer mt-5">
        <div class="container">
            <div class="text-center">
                <p>© <?php echo date('Y'); ?> E-Learning Platform. Admin Dashboard.</p>
                <p class="text-secondary">
                    <i class="fas fa-user-circle"></i> Logged in as: <?php echo htmlspecialchars($_SESSION['email']); ?>
                    | Last login: <?php echo date('F j, Y, g:i a', $_SESSION['login_time'] ?? time()); ?>
                </p>
            </div>
        </div>
    </footer>

    <script>
        // Simple animation for statistics cards
        document.addEventListener('DOMContentLoaded', function() {
            const statCards = document.querySelectorAll('.dashboard-grid .card');
            statCards.forEach(function(card, index) {
                card.style.animationDelay = (index * 0.1) + 's';
                card.classList.add('slide-up');
            });
            
            // Auto-hide success message after 5 seconds
            const successMessage = document.querySelector('.alert-success');
            if (successMessage) {
                setTimeout(function() {
                    successMessage.style.opacity = '0';
                    setTimeout(function() {
                        successMessage.style.display = 'none';
                    }, 300);
                }, 5000);
            }
            
            // Clear URL parameters to prevent message from showing on refresh
            if (window.location.search.includes('msg=')) {
                // Remove only the msg parameter from URL without reloading
                const url = new URL(window.location);
                url.searchParams.delete('msg');
                window.history.replaceState({}, document.title, url.toString());
            }
        });
    </script>
    
    <style>
        .btn-group {
            display: flex;
            gap: 0.25rem;
        }
        
        .btn-group .btn {
            padding: 0.25rem 0.5rem;
        }
        
        .close-btn {
            background: none;
            border: none;
            color: inherit;
            cursor: pointer;
            padding: 0;
            margin-left: 1rem;
        }
        
        .close-btn:hover {
            opacity: 0.8;
        }
    </style>
</body>
</html>