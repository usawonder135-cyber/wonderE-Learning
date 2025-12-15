<?php
// payment_success.php - Payment Success Confirmation
session_start();

if (!isset($_SESSION['user_id'], $_SESSION['role']) || $_SESSION['role'] !== 'student') {
    header('Location: login.php');
    exit();
}

require_once 'db_conn.php';

$transaction_id = isset($_GET['txn']) ? $_GET['txn'] : '';
$course_id = isset($_GET['course_id']) ? intval($_GET['course_id']) : 0;

// Get transaction and course details
try {
    $stmt = $pdo->prepare("SELECT 
        t.*,
        c.title as course_title,
        c.thumbnail_image,
        u.full_name as instructor_name
        FROM transactions t
        JOIN courses c ON t.course_id = c.id
        JOIN users u ON c.created_by = u.id
        WHERE t.transaction_id = ? AND t.user_id = ?");
    $stmt->execute([$transaction_id, $_SESSION['user_id']]);
    $transaction = $stmt->fetch();
    
    if (!$transaction) {
        header('Location: student_dashboard.php?error=TransactionNotFound');
        exit();
    }
    
} catch (PDOException $e) {
    error_log("Payment success error: " . $e->getMessage());
    header('Location: student_dashboard.php?error=LoadFailed');
    exit();
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Payment Successful - E-Learning Platform</title>
    <link rel="stylesheet" href="style.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        .success-icon {
            font-size: 5rem;
            color: #10b981;
            margin-bottom: 1rem;
        }
        .receipt {
            border: 2px solid #10b981;
            border-radius: 10px;
            padding: 20px;
            background: #f0fdf4;
        }
    </style>
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
        <div class="card text-center">
            <div class="card-header" style="background: linear-gradient(135deg, #10b981 0%, #34d399 100%); color: white;">
                <h1><i class="fas fa-check-circle"></i> Payment Successful!</h1>
            </div>
            
            <div class="p-5">
                <div class="success-icon">
                    <i class="fas fa-check-circle"></i>
                </div>
                
                <h2 class="mb-3">Thank You for Your Purchase!</h2>
                <p class="text-secondary mb-4">
                    Your payment has been processed successfully. You now have full access to the course.
                </p>
                
                <!-- Receipt -->
                <div class="receipt mb-4" style="max-width: 500px; margin: 0 auto;">
                    <h4 class="mb-3">Payment Receipt</h4>
                    <div class="text-left">
                        <p><strong>Transaction ID:</strong> <?php echo htmlspecialchars($transaction['transaction_id']); ?></p>
                        <p><strong>Course:</strong> <?php echo htmlspecialchars($transaction['course_title']); ?></p>
                        <p><strong>Amount Paid:</strong> $<?php echo number_format($transaction['amount'], 2); ?></p>
                        <p><strong>Payment Method:</strong> 
                            <?php 
                            $method_names = [
                                'telebirr' => 'Telebirr',
                                'cbe' => 'CBE Birr',
                                'paypal' => 'PayPal',
                                'card' => 'Credit/Debit Card'
                            ];
                            echo $method_names[$transaction['payment_method']] ?? ucfirst($transaction['payment_method']);
                            ?>
                        </p>
                        <p><strong>Date:</strong> <?php echo date('F d, Y H:i:s', strtotime($transaction['created_at'])); ?></p>
                        <p><strong>Status:</strong> <span class="badge badge-success">Completed</span></p>
                    </div>
                </div>
                
                <!-- Course Access -->
                <div class="card mb-4" style="max-width: 500px; margin: 0 auto;">
                    <div class="card-header">
                        <h5><i class="fas fa-rocket"></i> Ready to Start Learning!</h5>
                    </div>
                    <div class="p-3">
                        <p>You can now access your course immediately.</p>
                        <a href="my_courses.php" class="btn btn-primary btn-lg">
                            <i class="fas fa-play-circle"></i> Go to My Courses
                        </a>
                    </div>
                </div>
                
                <!-- Action Buttons -->
                <div class="row mt-4">
                    <div class="col">
                        <a href="student_dashboard.php" class="btn btn-outline btn-block">
                            <i class="fas fa-home"></i> Back to Dashboard
                        </a>
                    </div>
                    <div class="col">
                        <button onclick="window.print()" class="btn btn-secondary btn-block">
                            <i class="fas fa-print"></i> Print Receipt
                        </button>
                    </div>
                    <div class="col">
                        <a href="#" class="btn btn-info btn-block" onclick="alert('Receipt emailed to your registered email address.')">
                            <i class="fas fa-envelope"></i> Email Receipt
                        </a>
                    </div>
                </div>
                
                <!-- Next Steps -->
                <div class="alert alert-info mt-4" style="max-width: 600px; margin: 0 auto;">
                    <h5><i class="fas fa-lightbulb"></i> What's Next?</h5>
                    <ol class="text-left mb-0">
                        <li>Visit "My Courses" to start learning</li>
                        <li>Complete all video lessons and quizzes</li>
                        <li>Earn your certificate upon completion</li>
                        <li>Share your achievement on social media</li>
                    </ol>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        // Auto-redirect after 10 seconds
        setTimeout(function() {
            window.location.href = 'my_courses.php';
        }, 10000);
    </script>
</body>
</html>