<?php
// profile.php - Student Profile Page
session_start();

// Check if user is logged in and is student
if (!isset($_SESSION['user_id'], $_SESSION['role']) || $_SESSION['role'] !== 'student') {
    header('Location: login.php');
    exit();
}

// Include database connection
require_once 'db_conn.php';

// Initialize variables
$user_id = $_SESSION['user_id'];
$full_name = $_SESSION['full_name'] ?? '';
$email = $_SESSION['email'] ?? '';
$success_message = '';
$error_message = '';

// Fetch user details from database
try {
    $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
    $stmt->execute([$user_id]);
    $user = $stmt->fetch();
    
    if ($user) {
        $full_name = $user['full_name'];
        $email = $user['email'];
        $created_at = $user['created_at'];
    }
} catch (PDOException $e) {
    error_log("Error fetching user details: " . $e->getMessage());
    $error_message = "Unable to load profile information.";
}

// Fetch enrollment statistics
try {
    // Total enrolled courses
    $stmt = $pdo->prepare("SELECT COUNT(*) as total_courses FROM enrollments WHERE user_id = ?");
    $stmt->execute([$user_id]);
    $total_courses = $stmt->fetch()['total_courses'];
    
    // Recent enrollments
    $stmt = $pdo->prepare("SELECT c.title, e.enrollment_date 
                          FROM enrollments e 
                          JOIN courses c ON e.course_id = c.id 
                          WHERE e.user_id = ? 
                          ORDER BY e.enrollment_date DESC 
                          LIMIT 5");
    $stmt->execute([$user_id]);
    $recent_enrollments = $stmt->fetchAll();
} catch (PDOException $e) {
    error_log("Error fetching enrollment stats: " . $e->getMessage());
    $total_courses = 0;
    $recent_enrollments = [];
}

// Handle Profile Update (Name)
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['update_profile'])) {
    $new_name = trim($_POST['full_name'] ?? '');
    
    if (empty($new_name)) {
        $error_message = "Name cannot be empty.";
    } elseif (strlen($new_name) < 2) {
        $error_message = "Name must be at least 2 characters.";
    } else {
        try {
            $stmt = $pdo->prepare("UPDATE users SET full_name = ? WHERE id = ?");
            if ($stmt->execute([$new_name, $user_id])) {
                $full_name = $new_name;
                $_SESSION['full_name'] = $new_name;
                $success_message = "Profile updated successfully!";
            } else {
                $error_message = "Failed to update profile.";
            }
        } catch (PDOException $e) {
            error_log("Profile update error: " . $e->getMessage());
            $error_message = "Database error. Please try again.";
        }
    }
}

// Handle Password Change
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['change_password'])) {
    $current_password = $_POST['current_password'] ?? '';
    $new_password = $_POST['new_password'] ?? '';
    $confirm_password = $_POST['confirm_password'] ?? '';
    
    // Validation
    if (empty($current_password) || empty($new_password) || empty($confirm_password)) {
        $error_message = "All password fields are required.";
    } elseif ($new_password !== $confirm_password) {
        $error_message = "New passwords do not match.";
    } elseif (strlen($new_password) < 6) {
        $error_message = "New password must be at least 6 characters.";
    } else {
        // Verify current password
        if (password_verify($current_password, $user['password'])) {
            // Hash new password
            $hashed_password = password_hash($new_password, PASSWORD_BCRYPT);
            
            try {
                $stmt = $pdo->prepare("UPDATE users SET password = ? WHERE id = ?");
                if ($stmt->execute([$hashed_password, $user_id])) {
                    $success_message = "Password changed successfully!";
                } else {
                    $error_message = "Failed to change password.";
                }
            } catch (PDOException $e) {
                error_log("Password change error: " . $e->getMessage());
                $error_message = "Database error. Please try again.";
            }
        } else {
            $error_message = "Current password is incorrect.";
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>My Profile - E-Learning Platform</title>
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
                <li><a href="my_courses.php" class="nav-link"><i class="fas fa-book-open"></i> My Courses</a></li>
                <li><a href="certificates.php" class="nav-link"><i class="fas fa-certificate"></i> Certificates</a></li>
                <li><a href="profile.php" class="nav-link active"><i class="fas fa-user-circle"></i> Profile</a></li>
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
                    <h1>My Profile</h1>
                    <p class="text-secondary">Manage your account and view your learning progress</p>
                </div>
                <div>
                    <div class="badge badge-primary" style="font-size: 1rem; padding: 0.5rem 1rem;">
                        <i class="fas fa-user-graduate"></i> Student Account
                    </div>
                </div>
            </div>
        </div>

        <!-- Display Messages -->
        <?php if ($success_message): ?>
            <div class="alert alert-success fade-in mb-4">
                <i class="fas fa-check-circle"></i> <?php echo htmlspecialchars($success_message); ?>
                <button type="button" class="close-btn" onclick="this.parentElement.style.display='none'">
                    <i class="fas fa-times"></i>
                </button>
            </div>
        <?php endif; ?>

        <?php if ($error_message): ?>
            <div class="alert alert-danger fade-in mb-4">
                <i class="fas fa-exclamation-circle"></i> <?php echo htmlspecialchars($error_message); ?>
                <button type="button" class="close-btn" onclick="this.parentElement.style.display='none'">
                    <i class="fas fa-times"></i>
                </button>
            </div>
        <?php endif; ?>

        <div class="row">
            <!-- Left Column: Profile Info & Stats -->
            <div class="col">
                <!-- Profile Information -->
                <div class="card mb-4">
                    <div class="card-header">
                        <h3><i class="fas fa-user text-primary"></i> Profile Information</h3>
                    </div>
                    <div class="p-3">
                        <div class="row mb-3">
                            <div class="col">
                                <p><strong>Full Name:</strong></p>
                                <p class="text-secondary"><?php echo htmlspecialchars($full_name); ?></p>
                            </div>
                            <div class="col">
                                <p><strong>Email Address:</strong></p>
                                <p class="text-secondary"><?php echo htmlspecialchars($email); ?></p>
                            </div>
                        </div>
                        <div class="row">
                            <div class="col">
                                <p><strong>Account Type:</strong></p>
                                <p class="text-secondary">Student</p>
                            </div>
                            <div class="col">
                                <p><strong>Member Since:</strong></p>
                                <p class="text-secondary">
                                    <?php echo isset($created_at) ? date('F d, Y', strtotime($created_at)) : 'N/A'; ?>
                                </p>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Learning Statistics -->
                <div class="card mb-4">
                    <div class="card-header">
                        <h3><i class="fas fa-chart-line text-success"></i> Learning Statistics</h3>
                    </div>
                    <div class="p-3">
                        <div class="row text-center">
                            <div class="col">
                                <div class="card" style="background: linear-gradient(135deg, rgba(37, 99, 235, 0.1) 0%, rgba(37, 99, 235, 0.05) 100%);">
                                    <h2 style="color: #2563eb;"><?php echo $total_courses; ?></h2>
                                    <p class="text-secondary">Enrolled Courses</p>
                                </div>
                            </div>
                            <div class="col">
                                <div class="card" style="background: linear-gradient(135deg, rgba(16, 185, 129, 0.1) 0%, rgba(16, 185, 129, 0.05) 100%);">
                                    <h2 style="color: #10b981;">0</h2>
                                    <p class="text-secondary">Completed</p>
                                </div>
                            </div>
                            <div class="col">
                                <div class="card" style="background: linear-gradient(135deg, rgba(245, 158, 11, 0.1) 0%, rgba(245, 158, 11, 0.05) 100%);">
                                    <h2 style="color: #f59e0b;"><?php echo $total_courses; ?></h2>
                                    <p class="text-secondary">In Progress</p>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Recent Enrollments -->
                <div class="card">
                    <div class="card-header">
                        <h3><i class="fas fa-history text-warning"></i> Recent Enrollments</h3>
                    </div>
                    <div class="p-3">
                        <?php if (!empty($recent_enrollments)): ?>
                            <ul class="list-unstyled">
                                <?php foreach ($recent_enrollments as $enrollment): ?>
                                    <li class="mb-2 p-2" style="border-left: 3px solid #3b82f6; background: rgba(59, 130, 246, 0.05);">
                                        <strong><?php echo htmlspecialchars($enrollment['title']); ?></strong><br>
                                        <small class="text-secondary">
                                            <i class="far fa-calendar"></i> 
                                            Enrolled: <?php echo date('M d, Y', strtotime($enrollment['enrollment_date'])); ?>
                                        </small>
                                    </li>
                                <?php endforeach; ?>
                            </ul>
                        <?php else: ?>
                            <p class="text-center text-secondary">
                                <i class="fas fa-book-open"></i><br>
                                No courses enrolled yet.
                            </p>
                        <?php endif; ?>
                    </div>
                </div>
            </div>

            <!-- Right Column: Update Forms -->
            <div class="col">
                <!-- Update Profile Form -->
                <div class="card mb-4">
                    <div class="card-header">
                        <h3><i class="fas fa-edit text-primary"></i> Update Profile</h3>
                    </div>
                    <div class="p-3">
                        <form method="POST" action="">
                            <div class="form-group">
                                <label for="full_name" class="form-label">Full Name</label>
                                <input 
                                    type="text" 
                                    id="full_name" 
                                    name="full_name" 
                                    class="form-control" 
                                    value="<?php echo htmlspecialchars($full_name); ?>"
                                    required
                                >
                            </div>
                            <button type="submit" name="update_profile" class="btn btn-primary btn-block">
                                <i class="fas fa-save"></i> Update Profile
                            </button>
                        </form>
                    </div>
                </div>

                <!-- Change Password Form -->
                <div class="card mb-4">
                    <div class="card-header">
                        <h3><i class="fas fa-lock text-success"></i> Change Password</h3>
                    </div>
                    <div class="p-3">
                        <form method="POST" action="">
                            <div class="form-group">
                                <label for="current_password" class="form-label">Current Password</label>
                                <input 
                                    type="password" 
                                    id="current_password" 
                                    name="current_password" 
                                    class="form-control" 
                                    required
                                >
                            </div>
                            <div class="form-group">
                                <label for="new_password" class="form-label">New Password</label>
                                <input 
                                    type="password" 
                                    id="new_password" 
                                    name="new_password" 
                                    class="form-control" 
                                    required
                                    minlength="6"
                                >
                                <small class="form-text">Minimum 6 characters</small>
                            </div>
                            <div class="form-group">
                                <label for="confirm_password" class="form-label">Confirm New Password</label>
                                <input 
                                    type="password" 
                                    id="confirm_password" 
                                    name="confirm_password" 
                                    class="form-control" 
                                    required
                                >
                            </div>
                            <button type="submit" name="change_password" class="btn btn-success btn-block">
                                <i class="fas fa-key"></i> Change Password
                            </button>
                        </form>
                    </div>
                </div>

                <!-- Account Information -->
                <div class="card">
                    <div class="card-header">
                        <h3><i class="fas fa-info-circle text-info"></i> Account Information</h3>
                    </div>
                    <div class="p-3">
                        <div class="alert alert-info">
                            <i class="fas fa-shield-alt"></i> 
                            <strong>Security Tips:</strong>
                            <ul class="mb-0 mt-2">
                                <li>Use a strong, unique password</li>
                                <li>Never share your login credentials</li>
                                <li>Log out after each session on shared devices</li>
                                <li>Contact support if you notice suspicious activity</li>
                            </ul>
                        </div>
                        <div class="text-center">
                            <a href="student_dashboard.php" class="btn btn-outline btn-block">
                                <i class="fas fa-arrow-left"></i> Back to Dashboard
                            </a>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Footer -->
    <footer class="footer mt-5">
        <div class="container">
            <div class="text-center">
                <p>© <?php echo date('Y'); ?> E-Learning Platform. Student Profile.</p>
                <p class="text-secondary">
                    <i class="fas fa-user-graduate"></i> 
                    Student ID: #<?php echo $user_id; ?> | 
                    Last updated: <?php echo date('F j, Y, g:i a'); ?>
                </p>
            </div>
        </div>
    </footer>

    <!-- JavaScript -->
    <script>
        // Initialize when page is fully loaded
        function initProfile() {
            autoHideAlerts();
            setupPasswordValidation();
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

        // Password validation
        function setupPasswordValidation() {
            var newPassword = document.getElementById('new_password');
            var confirmPassword = document.getElementById('confirm_password');
            
            if (newPassword && confirmPassword) {
                function validatePasswords() {
                    if (newPassword.value !== confirmPassword.value) {
                        confirmPassword.style.borderColor = '#ef4444';
                        confirmPassword.setCustomValidity('Passwords do not match');
                    } else {
                        confirmPassword.style.borderColor = '#e5e7eb';
                        confirmPassword.setCustomValidity('');
                    }
                }
                
                newPassword.addEventListener('input', validatePasswords);
                confirmPassword.addEventListener('input', validatePasswords);
            }
        }

        // Initialize when DOM is ready
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', initProfile);
        } else {
            initProfile();
        }
    </script>
    
    <style>
        .list-unstyled {
            list-style: none;
            padding-left: 0;
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
        
        /* Responsive layout */
        @media (max-width: 768px) {
            .row {
                flex-direction: column;
            }
            
            .col {
                width: 100%;
                margin-bottom: 1.5rem;
            }
        }
    </style>
</body>
</html>