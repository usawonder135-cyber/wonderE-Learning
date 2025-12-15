<?php
// login.php - User Login Page

// Start session (must be at the very beginning)
session_start();

// Include database connection
require_once 'db_conn.php';

// Initialize variables

$email = '';
$error_message = '';
$success_message = '';

// Check if user is already logged in

if (isset($_SESSION['user_id'])) {
    // Redirect based on role
    if ($_SESSION['role'] === 'admin') {
        header('Location: admin_dashboard.php');
        exit();
    } else {
        header('Location: student_dashboard.php');
        exit();
    }
}



// Check if form is submitted
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Sanitize and validate inputs
    $email = filter_var(trim($_POST['email']), FILTER_SANITIZE_EMAIL);
    $password = $_POST['password'];
    


    // Validate inputs
    if (empty($email) || empty($password)) {
        $error_message = "Please fill in all fields.";
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $error_message = "Please enter a valid email address.";
    } else {
        try {
            // Prepare SQL statement to find user
            $stmt = $pdo->prepare("SELECT id, full_name, email, password, role FROM users WHERE email = :email");
            $stmt->execute(['email' => $email]);
            $user = $stmt->fetch();
            
            if ($user) {
                // Verify password
                if (password_verify($password, $user['password'])) {
                    // Login successful - set session variables
                    $_SESSION['user_id'] = $user['id'];
                    $_SESSION['full_name'] = $user['full_name'];
                    $_SESSION['email'] = $user['email'];
                    $_SESSION['role'] = $user['role'];
                    $_SESSION['logged_in'] = true;
                    $_SESSION['login_time'] = time();
                    
                    // Set success message
                    $success_message = "Login successful! Redirecting...";
                    
                    // Redirect based on role
                    if ($user['role'] === 'admin') {
                        header('Refresh: 1; URL=admin_dashboard.php');
                    } else {
                        header('Refresh: 1; URL=student_dashboard.php');
                    }
                    
                } else {
                    $error_message = "Invalid email or password.";
                }
            } else {
                $error_message = "Invalid email or password.";
            }
        } catch (PDOException $e) {
            $error_message = "Login failed. Please try again later.";
            error_log("Login Error: " . $e->getMessage());
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - E-Learning Platform</title>
    <link rel="stylesheet" href="style.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
</head>
<body>
    <div class="container">
        <div class="flex-center" style="min-height: 100vh;">
            <div class="card" style="width: 100%; max-width: 450px; margin: 2rem 0;">
                <!-- Logo Header -->
                <div class="text-center mb-4">
                    <div class="logo" style="font-size: 2.5rem; margin-bottom: 0.5rem;">
                        <i class="fas fa-graduation-cap" style="color: #2563eb;"></i>
                        <span>E-Learn</span>
                    </div>
                    <h1 style="margin-bottom: 0.5rem;">Welcome Back</h1>
                    <p class="text-secondary">Sign in to continue your learning journey</p>
                </div>
                
                <!-- Display Messages -->
                <?php if ($error_message): ?>
                    <div class="alert alert-danger fade-in">
                        <i class="fas fa-exclamation-circle"></i>
                        <?php echo htmlspecialchars($error_message); ?>
                    </div>
                <?php endif; ?>
                
                <?php if ($success_message): ?>
                    <div class="alert alert-success fade-in">
                        <i class="fas fa-check-circle"></i>
                        <?php echo htmlspecialchars($success_message); ?>
                    </div>
                <?php endif; ?>
                
                <!-- Login Form -->
                <form method="POST" action="<?php echo htmlspecialchars($_SERVER['PHP_SELF']); ?>">
                    <div class="form-group">
                        <label for="email" class="form-label">
                            <i class="fas fa-envelope" style="margin-right: 0.5rem;"></i>
                            Email Address
                        </label>
                        <input 
                            type="email" 
                            id="email" 
                            name="email" 
                            class="form-control" 
                            placeholder="Enter your email"
                            value="<?php echo htmlspecialchars($email); ?>"
                            required
                        >
                    </div>
                    
                    <div class="form-group">
                        <label for="password" class="form-label">
                            <i class="fas fa-lock" style="margin-right: 0.5rem;"></i>
                            Password
                        </label>
                        <input 
                            type="password" 
                            id="password" 
                            name="password" 
                            class="form-control" 
                            placeholder="Enter your password"
                            required
                        >
                        <div class="text-right mt-1">
                            <a href="forgot_password.php" style="font-size: 0.875rem;">
                                Forgot password?
                            </a>
                        </div>
                    </div>
                    
                    <div class="form-group">
                        <button type="submit" class="btn btn-primary btn-block btn-lg">
                            <i class="fas fa-sign-in-alt" style="margin-right: 0.5rem;"></i>
                            Login
                        </button>
                    </div>
                </form>
                
                <!-- Demo Accounts Info -->
                <div class="card" style="background-color: rgba(37, 99, 235, 0.05); border: 1px solid rgba(37, 99, 235, 0.2); margin-top: 1.5rem;">
                    <div class="text-center" style="font-size: 0.875rem;">
                        <p style="margin-bottom: 0.5rem; font-weight: 500; color: #2563eb;">
                            <i class="fas fa-info-circle"></i> Demo Accounts
                        </p>
                        <p style="margin-bottom: 0.25rem; color: #6b7280;">
                            <strong>Admin:</strong> admin@test.com / 123456
                        </p>
                        <p style="color: #6b7280;">
                            <strong>Student:</strong> student@test.com / 123456
                        </p>
                    </div>
                </div>
                
                <!-- Registration Link -->
                <div class="text-center mt-4">
                    <p style="color: var(--text-secondary);">
                        Don't have an account?
                        <a href="register.php" style="font-weight: 600;">
                            Register here
                        </a>
                    </p>
                </div>
                
                <!-- Back to Home -->
                <div class="text-center mt-2">
                    <a href="index.php" style="color: var(--text-secondary); font-size: 0.875rem;">
                        <i class="fas fa-arrow-left" style="margin-right: 0.5rem;"></i>
                        Back to Home
                    </a>
                </div>
            </div>
        </div>
    </div>

    <script>
        // Add some interactivity
        document.addEventListener('DOMContentLoaded', function() {
            // Focus on email field
            document.getElementById('email').focus();
            
            // Toggle password visibility (optional feature)
            const passwordField = document.getElementById('password');
            const toggleBtn = document.createElement('button');
            toggleBtn.type = 'button';
            toggleBtn.innerHTML = '<i class="fas fa-eye"></i>';
            toggleBtn.style.position = 'absolute';
            toggleBtn.style.right = '10px';
            toggleBtn.style.top = '50%';
            toggleBtn.style.transform = 'translateY(-50%)';
            toggleBtn.style.background = 'none';
            toggleBtn.style.border = 'none';
            toggleBtn.style.color = '#6b7280';
            toggleBtn.style.cursor = 'pointer';
            
            // Position the toggle button
            passwordField.style.position = 'relative';
            passwordField.parentNode.style.position = 'relative';
            
            // Insert the toggle button
            passwordField.parentNode.appendChild(toggleBtn);
            
            toggleBtn.addEventListener('click', function() {
                const type = passwordField.getAttribute('type') === 'password' ? 'text' : 'password';
                passwordField.setAttribute('type', type);
                this.innerHTML = type === 'password' ? '<i class="fas fa-eye"></i>' : '<i class="fas fa-eye-slash"></i>';
            });
        });
    </script>
</body>
</html>