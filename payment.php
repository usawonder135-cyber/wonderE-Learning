<?php
// payment.php - Payment Processing Page
session_start();

if (!isset($_SESSION['user_id'], $_SESSION['role']) || $_SESSION['role'] !== 'student') {
    header('Location: login.php');
    exit();
}

require_once 'db_conn.php';

$user_id = $_SESSION['user_id'];
$course_id = isset($_GET['course_id']) ? intval($_GET['course_id']) : 0;
$error_message = '';
$success_message = '';

// Get course details
try {
    $stmt = $pdo->prepare("SELECT 
        c.*,
        u.full_name as instructor_name
        FROM courses c
        JOIN users u ON c.created_by = u.id
        WHERE c.id = ?");
    $stmt->execute([$course_id]);
    $course = $stmt->fetch();
    
    if (!$course) {
        header('Location: student_dashboard.php?error=CourseNotFound');
        exit();
    }
    
    // Check if already enrolled
    $stmt = $pdo->prepare("SELECT id FROM enrollments WHERE user_id = ? AND course_id = ?");
    $stmt->execute([$user_id, $course_id]);
    if ($stmt->fetch()) {
        header('Location: student_dashboard.php?error=AlreadyEnrolled');
        exit();
    }
    
} catch (PDOException $e) {
    error_log("Payment page error: " . $e->getMessage());
    header('Location: student_dashboard.php?error=PaymentLoadFailed');
    exit();
}

// Handle payment submission
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['process_payment'])) {
    $payment_method = trim($_POST['payment_method'] ?? '');
    $card_number = trim($_POST['card_number'] ?? '');
    $card_expiry = trim($_POST['card_expiry'] ?? '');
    $card_cvv = trim($_POST['card_cvv'] ?? '');
    
    // Validate payment method
    $valid_methods = ['telebirr', 'cbe', 'paypal', 'card'];
    if (!in_array($payment_method, $valid_methods)) {
        $error_message = "Please select a valid payment method.";
    } elseif ($payment_method === 'card' && (empty($card_number) || empty($card_expiry) || empty($card_cvv))) {
        $error_message = "Please fill in all card details.";
    } else {
        try {
            $pdo->beginTransaction();
            
            // Generate unique transaction ID
            $transaction_id = 'TXN-' . time() . '-' . rand(1000, 9999);
            $amount = $course['price'];
            
            // Record transaction
            $stmt = $pdo->prepare("INSERT INTO transactions 
                (user_id, course_id, amount, payment_method, transaction_id, status, created_at)
                VALUES (?, ?, ?, ?, ?, 'completed', NOW())");
            $stmt->execute([$user_id, $course_id, $amount, $payment_method, $transaction_id]);
            
            // Enroll student in course
            $stmt = $pdo->prepare("INSERT INTO enrollments (user_id, course_id, enrollment_date)
                VALUES (?, ?, NOW())");
            $stmt->execute([$user_id, $course_id]);
            
            $pdo->commit();
            
            // Redirect with success
            header('Location: payment_success.php?txn=' . urlencode($transaction_id) . '&course_id=' . $course_id);
            exit();
            
        } catch (PDOException $e) {
            $pdo->rollBack();
            error_log("Payment processing error: " . $e->getMessage());
            $error_message = "Payment failed. Please try again or contact support.";
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Complete Payment - E-Learning Platform</title>
    <link rel="stylesheet" href="style.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        .payment-method {
            border: 2px solid #e5e7eb;
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 10px;
            cursor: pointer;
            transition: all 0.3s;
        }
        .payment-method:hover, .payment-method.selected {
            border-color: #2563eb;
            background-color: rgba(37, 99, 235, 0.05);
        }
        .payment-method input[type="radio"] {
            margin-right: 10px;
        }
        .card-details {
            display: none;
            margin-top: 15px;
            padding: 15px;
            background: #f8fafc;
            border-radius: 8px;
            border-left: 4px solid #2563eb;
        }
    </style>
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
                <li><a href="logout.php" class="btn btn-danger btn-sm"><i class="fas fa-sign-out-alt"></i> Logout</a></li>
            </ul>
        </div>
    </nav>

    <div class="container mt-4">
        <div class="row">
            <!-- Order Summary -->
            <div class="col">
                <div class="card mb-4">
                    <div class="card-header">
                        <h3><i class="fas fa-shopping-cart"></i> Order Summary</h3>
                    </div>
                    <div class="p-4">
                        <div class="d-flex align-items-center mb-4">
                            <?php if (!empty($course['thumbnail_image']) && file_exists($course['thumbnail_image'])): ?>
                            <img src="<?php echo htmlspecialchars($course['thumbnail_image']); ?>" 
                                 alt="<?php echo htmlspecialchars($course['title']); ?>"
                                 style="width: 100px; height: 70px; object-fit: cover; border-radius: 6px; margin-right: 15px;">
                            <?php endif; ?>
                            <div>
                                <h4><?php echo htmlspecialchars($course['title']); ?></h4>
                                <p class="text-secondary mb-0">
                                    <i class="fas fa-user-tie"></i> <?php echo htmlspecialchars($course['instructor_name']); ?>
                                </p>
                            </div>
                        </div>
                        
                        <div class="card" style="background: #f8fafc;">
                            <div class="p-3">
                                <div class="d-flex justify-content-between mb-2">
                                    <span>Course Price:</span>
                                    <strong>$<?php echo number_format($course['price'], 2); ?></strong>
                                </div>
                                <div class="d-flex justify-content-between mb-2">
                                    <span>Platform Fee:</span>
                                    <span>$0.00</span>
                                </div>
                                <hr>
                                <div class="d-flex justify-content-between">
                                    <span class="font-weight-bold">Total:</span>
                                    <strong class="text-primary" style="font-size: 1.2rem;">
                                        $<?php echo number_format($course['price'], 2); ?>
                                    </strong>
                                </div>
                            </div>
                        </div>
                        
                        <div class="alert alert-info mt-3">
                            <i class="fas fa-shield-alt"></i>
                            <strong>Secure Payment:</strong> Your payment information is encrypted and secure.
                        </div>
                    </div>
                </div>
            </div>

            <!-- Payment Form -->
            <div class="col">
                <div class="card">
                    <div class="card-header">
                        <h3><i class="fas fa-credit-card"></i> Payment Details</h3>
                    </div>
                    <div class="p-4">
                        <?php if ($error_message): ?>
                        <div class="alert alert-danger">
                            <i class="fas fa-exclamation-circle"></i> <?php echo htmlspecialchars($error_message); ?>
                        </div>
                        <?php endif; ?>

                        <form method="POST" id="payment-form">
                            <h5 class="mb-3">Select Payment Method</h5>
                            
                            <!-- Telebirr -->
                            <div class="payment-method" onclick="selectPaymentMethod('telebirr')">
                                <input type="radio" id="telebirr" name="payment_method" value="telebirr" required>
                                <label for="telebirr" style="cursor: pointer; width: 100%;">
                                    <i class="fas fa-mobile-alt" style="color: #3b82f6;"></i>
                                    <strong>Telebirr</strong>
                                    <span class="text-secondary float-right">Pay with Telebirr mobile money</span>
                                </label>
                            </div>
                            
                            <!-- CBE Birr -->
                            <div class="payment-method" onclick="selectPaymentMethod('cbe')">
                                <input type="radio" id="cbe" name="payment_method" value="cbe" required>
                                <label for="cbe" style="cursor: pointer; width: 100%;">
                                    <i class="fas fa-university" style="color: #10b981;"></i>
                                    <strong>CBE Birr</strong>
                                    <span class="text-secondary float-right">Commercial Bank of Ethiopia</span>
                                </label>
                            </div>
                            
                            <!-- PayPal -->
                            <div class="payment-method" onclick="selectPaymentMethod('paypal')">
                                <input type="radio" id="paypal" name="payment_method" value="paypal" required>
                                <label for="paypal" style="cursor: pointer; width: 100%;">
                                    <i class="fab fa-paypal" style="color: #003087;"></i>
                                    <strong>PayPal</strong>
                                    <span class="text-secondary float-right">International payments</span>
                                </label>
                            </div>
                            
                            <!-- Credit/Debit Card -->
                            <div class="payment-method" onclick="selectPaymentMethod('card')">
                                <input type="radio" id="card" name="payment_method" value="card" required>
                                <label for="card" style="cursor: pointer; width: 100%;">
                                    <i class="fas fa-credit-card" style="color: #8b5cf6;"></i>
                                    <strong>Credit/Debit Card</strong>
                                    <span class="text-secondary float-right">Visa, Mastercard, American Express</span>
                                </label>
                            </div>
                            
                            <!-- Card Details (shown only when card selected) -->
                            <div id="card-details" class="card-details">
                                <h6 class="mb-3">Card Information</h6>
                                <div class="form-group">
                                    <label for="card_number">Card Number</label>
                                    <input type="text" id="card_number" name="card_number" 
                                           class="form-control" placeholder="1234 5678 9012 3456"
                                           maxlength="19" oninput="formatCardNumber(this)">
                                </div>
                                <div class="row">
                                    <div class="col">
                                        <div class="form-group">
                                            <label for="card_expiry">Expiry Date</label>
                                            <input type="text" id="card_expiry" name="card_expiry" 
                                                   class="form-control" placeholder="MM/YY"
                                                   maxlength="5" oninput="formatExpiry(this)">
                                        </div>
                                    </div>
                                    <div class="col">
                                        <div class="form-group">
                                            <label for="card_cvv">CVV</label>
                                            <input type="text" id="card_cvv" name="card_cvv" 
                                                   class="form-control" placeholder="123"
                                                   maxlength="4" oninput="this.value = this.value.replace(/[^0-9]/g, '')">
                                        </div>
                                    </div>
                                </div>
                            </div>
                            
                            <div class="alert alert-warning mt-4">
                                <i class="fas fa-info-circle"></i>
                                <small>
                                    <strong>Demo Notice:</strong> This is a simulation for educational purposes. 
                                    No real payment will be processed. Transaction will be recorded for demonstration.
                                </small>
                            </div>
                            
                            <div class="mt-4">
                                <button type="submit" name="process_payment" class="btn btn-success btn-lg btn-block">
                                    <i class="fas fa-lock"></i> Pay $<?php echo number_format($course['price'], 2); ?> Now
                                </button>
                                <a href="student_dashboard.php" class="btn btn-secondary btn-block mt-2">
                                    <i class="fas fa-times"></i> Cancel Payment
                                </a>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        function selectPaymentMethod(method) {
            // Update radio button
            document.getElementById(method).checked = true;
            
            // Update UI
            document.querySelectorAll('.payment-method').forEach(el => {
                el.classList.remove('selected');
            });
            event.currentTarget.classList.add('selected');
            
            // Show/hide card details
            const cardDetails = document.getElementById('card-details');
            if (method === 'card') {
                cardDetails.style.display = 'block';
            } else {
                cardDetails.style.display = 'none';
            }
        }
        
        function formatCardNumber(input) {
            let value = input.value.replace(/\s+/g, '').replace(/[^0-9]/gi, '');
            let matches = value.match(/\d{4,16}/g);
            let match = matches && matches[0] || '';
            let parts = [];
            
            for (let i = 0, len = match.length; i < len; i += 4) {
                parts.push(match.substring(i, i + 4));
            }
            
            if (parts.length) {
                input.value = parts.join(' ');
            } else {
                input.value = value;
            }
        }
        
        function formatExpiry(input) {
            let value = input.value.replace(/\D/g, '');
            if (value.length >= 2) {
                input.value = value.substring(0, 2) + '/' + value.substring(2, 4);
            }
        }
        
        // Initialize
        document.addEventListener('DOMContentLoaded', function() {
            // Select first payment method by default
            selectPaymentMethod('telebirr');
        });
    </script>
</body>
</html>