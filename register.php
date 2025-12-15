<?php
// register.php - Simple registration
session_start();
require_once 'db_conn.php';

$error = '';
$success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $full_name = trim($_POST['full_name'] ?? '');
    $email = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';
    $confirm_password = $_POST['confirm_password'] ?? '';
    $role = 'student'; // Default role
    
    if (empty($full_name) || empty($email) || empty($password)) {
        $error = "All fields are required";
    } elseif ($password !== $confirm_password) {
        $error = "Passwords do not match";
    } elseif (strlen($password) < 6) {
        $error = "Password must be at least 6 characters";
    } else {
        try {
            // Check if email exists
            $stmt = $pdo->prepare("SELECT id FROM users WHERE email = ?");
            $stmt->execute([$email]);
            if ($stmt->fetch()) {
                $error = "Email already registered";
            } else {
                // Hash password
                $hashed_password = password_hash($password, PASSWORD_BCRYPT);
                
                // Insert user
                $stmt = $pdo->prepare("INSERT INTO users (full_name, email, password, role, created_at) 
                                      VALUES (?, ?, ?, ?, NOW())");
                $stmt->execute([$full_name, $email, $hashed_password, $role]);
                
                $success = "Registration successful! You can now login.";
            }
        } catch (PDOException $e) {
            $error = "Registration failed. Please try again.";
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register - E-Learning Platform</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="container" style="max-width: 500px; margin: 100px auto;">
        <div class="card">
            <div class="card-header">
                <h2><i class="fas fa-user-plus"></i> Create Account</h2>
                <p class="text-secondary">Join our e-learning community</p>
            </div>
            
            <div class="p-4">
                <?php if ($error): ?>
                <div class="alert alert-danger"><?php echo htmlspecialchars($error); ?></div>
                <?php endif; ?>
                
                <?php if ($success): ?>
                <div class="alert alert-success"><?php echo htmlspecialchars($success); ?></div>
                <?php endif; ?>
                
                <form method="POST" action="">
                    <div class="form-group">
                        <label for="full_name">Full Name</label>
                        <input type="text" id="full_name" name="full_name" class="form-control" 
                               value="<?php echo htmlspecialchars($_POST['full_name'] ?? ''); ?>" required>
                    </div>
                    
                    <div class="form-group">
                        <label for="email">Email Address</label>
                        <input type="email" id="email" name="email" class="form-control"
                               value="<?php echo htmlspecialchars($_POST['email'] ?? ''); ?>" required>
                    </div>
                    
                    <div class="form-group">
                        <label for="password">Password</label>
                        <input type="password" id="password" name="password" class="form-control" required>
                        <small class="text-secondary">Minimum 6 characters</small>
                    </div>
                    
                    <div class="form-group">
                        <label for="confirm_password">Confirm Password</label>
                        <input type="password" id="confirm_password" name="confirm_password" class="form-control" required>
                    </div>
                    
                    <div class="form-check mb-3">
                        <input type="checkbox" class="form-check-input" id="terms" required>
                        <label class="form-check-label" for="terms">
                            I agree to the <a href="#">Terms of Service</a>
                        </label>
                    </div>
                    
                    <button type="submit" class="btn btn-primary btn-block">Register</button>
                    
                    <div class="text-center mt-3">
                        <p>Already have an account? <a href="login.php">Login here</a></p>
                    </div>
                </form>
            </div>
        </div>
    </div>
</body>
</html>
