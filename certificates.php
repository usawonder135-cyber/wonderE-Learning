<?php
// certificates.php - Student Certificates Page
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

// We'll create a simple "certificate" concept for demonstration


// Fetch enrolled courses that could have certificates
try {
    // Get all enrolled courses
    $stmt = $pdo->prepare("SELECT c.id, c.title, c.description, 
                                  u.full_name as instructor_name,
                                  e.enrollment_date
                           FROM enrollments e
                           JOIN courses c ON e.course_id = c.id
                           JOIN users u ON c.created_by = u.id
                           WHERE e.user_id = ?
                           ORDER BY e.enrollment_date DESC");
    $stmt->execute([$user_id]);
    $enrolled_courses = $stmt->fetchAll();

    // For demo: Let's mark some courses as "completed"

    // Check actual quiz completion instead of demo
    $certificates = [];

    foreach ($enrolled_courses as $course) {
        // Check if user has passed the quiz for this course
        try {
            $stmt = $pdo->prepare("SELECT 
            q.id as quiz_id,
            up.passed,
            up.best_score,
            up.last_attempt
            FROM quizzes q
            LEFT JOIN user_quiz_progress up ON q.id = up.quiz_id AND up.user_id = ?
            WHERE q.course_id = ? AND q.is_active = TRUE
            LIMIT 1");

            $stmt->execute([$user_id, $course['id']]);
            $quiz_result = $stmt->fetch();

            // If quiz exists and user passed it, generate certificate
            if ($quiz_result && $quiz_result['passed']) {
                $certificate_id = 'CERT-' . $course['id'] . '-' . $user_id . '-' . time();
                $completion_date = date('Y-m-d', strtotime($quiz_result['last_attempt']));

                $certificates[] = [
                    'certificate_id' => $certificate_id,
                    'course_id' => $course['id'],
                    'course_title' => $course['title'],
                    'instructor_name' => $course['instructor_name'],
                    'enrollment_date' => $course['enrollment_date'],
                    'completion_date' => $completion_date,
                    'student_name' => $full_name,
                    'quiz_score' => $quiz_result['best_score'], // Add quiz score to certificate
                    'status' => 'completed'
                ];
            }
        } catch (PDOException $e) {
            error_log("Certificate quiz check error: " . $e->getMessage());
            // Continue with other courses
        }
    }

    $total_certificates = count($certificates);
} catch (PDOException $e) {
    error_log("Error fetching certificates: " . $e->getMessage());
    $error_message = "Unable to load certificate information.";
    $enrolled_courses = [];
    $certificates = [];
    $total_certificates = 0;
}

// Handle certificate generation request
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['generate_certificate'])) {
    $course_id = intval($_POST['course_id'] ?? 0);

    // 1. Verify user is enrolled
    $selected_course = null;
    foreach ($enrolled_courses as $course) {
        if ($course['id'] == $course_id) {
            $selected_course = $course;
            break;
        }
    }

    if ($selected_course) {
        // 2. Check if user has passed the quiz for this course
        try {
            $stmt = $pdo->prepare("SELECT 
                up.passed,
                up.best_score,
                q.title as quiz_title
                FROM user_quiz_progress up
                JOIN quizzes q ON up.quiz_id = q.id
                WHERE up.user_id = ? AND up.course_id = ? AND up.passed = TRUE
                LIMIT 1");

            $stmt->execute([$user_id, $course_id]);
            $quiz_passed = $stmt->fetch();

            if (!$quiz_passed) {
                $error_message = "You must pass the course quiz before generating a certificate.";
            } else {
                // 3. Generate certificate (user has passed quiz)
                $certificate_id = 'CERT-' . $course_id . '-' . $user_id . '-' . time();
                $completion_date = date('F d, Y');

                $new_certificate = [
                    'certificate_id' => $certificate_id,
                    'course_id' => $course_id,
                    'course_title' => $selected_course['title'],
                    'instructor_name' => $selected_course['instructor_name'],
                    'enrollment_date' => $selected_course['enrollment_date'],
                    'completion_date' => $completion_date,
                    'student_name' => $full_name,
                    'quiz_score' => $quiz_passed['best_score'], // Include quiz score
                    'quiz_title' => $quiz_passed['quiz_title'], // Include quiz name
                    'status' => 'generated'
                ];

                // Add to certificates array
                $certificates[] = $new_certificate;
                $total_certificates++;

                $success_message = "Certificate generated successfully! 
                                   Quiz: " . htmlspecialchars($quiz_passed['quiz_title']) .
                    " | Score: " . $quiz_passed['best_score'] . "%";
            }
        } catch (PDOException $e) {
            error_log("Certificate generation check error: " . $e->getMessage());
            $error_message = "Unable to verify quiz completion. Please try again.";
        }
    } else {
        $error_message = "Invalid course selected";
    }
}

// Handle certificate view/download
if (isset($_GET['view_certificate'])) {
    $cert_id = $_GET['view_certificate'];
    $selected_certificate = null;

    foreach ($certificates as $cert) {
        if ($cert['certificate_id'] === $cert_id) {
            $selected_certificate = $cert;
            break;
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>My Certificates - E-Learning Platform</title>
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
                <li><a href="certificates.php" class="nav-link active"><i class="fas fa-certificate"></i> Certificates</a></li>
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
                    <h1>My Certificates</h1>
                    <p class="text-secondary">View and manage your course completion certificates</p>
                </div>
                <div>
                    <div class="badge badge-primary" style="font-size: 1rem; padding: 0.5rem 1rem;">
                        <i class="fas fa-award"></i> <?php echo $total_certificates; ?> Certificates
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

        <!-- Certificate View Modal (if requested) -->
        <?php if (isset($_GET['view_certificate']) && isset($selected_certificate)): ?>
            <div class="card mb-4" style="border: 2px solid #3b82f6;">
                <div class="card-header" style="background: linear-gradient(135deg, #3b82f6 0%, #1d4ed8 100%); color: white;">
                    <h3><i class="fas fa-certificate"></i> Certificate Preview</h3>
                </div>
                <div class="p-4 text-center" style="background: #f8fafc; min-height: 400px;">
                    <!-- Certificate Design -->
                    <div style="border: 3px solid #d1d5db; padding: 3rem; background: white; max-width: 800px; margin: 0 auto; position: relative;">
                        <!-- Decorative border -->
                        <div style="position: absolute; top: 10px; left: 10px; right: 10px; bottom: 10px; border: 2px solid #3b82f6; pointer-events: none;"></div>

                        <!-- Certificate Header -->
                        <div style="margin-bottom: 2rem;">
                            <h1 style="color: #1d4ed8; font-size: 2.5rem; margin-bottom: 0.5rem;">
                                <i class="fas fa-graduation-cap"></i> Certificate of Completion
                            </h1>
                            <p style="color: #6b7280;">This certifies that</p>
                        </div>

                        <!-- Student Name -->
                        <div style="margin: 2rem 0; padding: 1.5rem; background: linear-gradient(135deg, rgba(59, 130, 246, 0.1) 0%, rgba(29, 78, 216, 0.05) 100%);">
                            <h2 style="color: #1e293b; font-size: 2rem; margin: 0;">
                                <?php echo htmlspecialchars($selected_certificate['student_name']); ?>
                            </h2>
                        </div>

                        <!-- Course Details -->
                        <div style="margin: 2rem 0;">
                            <p style="color: #6b7280; font-size: 1.1rem;">
                                has successfully completed the course
                            </p>
                            <h3 style="color: #3b82f6; font-size: 1.5rem; margin: 1rem 0;">
                                "<?php echo htmlspecialchars($selected_certificate['course_title']); ?>"
                            </h3>
                            <?php if (isset($selected_certificate['quiz_score']) || isset($selected_certificate['quiz_title'])): ?>
                                <div style="margin: 1rem 0; padding: 0.5rem; background: rgba(59, 130, 246, 0.05); border-radius: 4px;">
                                    <p style="margin: 0; color:#6b7280; font-size: 0.9rem;">
                                        <strong>Assessment:</strong>
                                        <?php echo isset($selected_certificate['quiz_title']) ? htmlspecialchars($selected_certificate['quiz_title']) : 'Final Quiz'; ?>
                                        |
                                        <strong>Score:</strong>
                                        <?php echo isset($selected_certificate['quiz_score']) ? $selected_certificate['quiz_score'] . '%' : 'Passed'; ?>
                                    </p>
                                </div>
                            <?php endif; ?>
                            <p style="color: #6b7280;">
                                under the instruction of <strong><?php echo htmlspecialchars($selected_certificate['instructor_name']); ?></strong>
                            </p>
                        </div>

                        <!-- Dates and ID -->
                        <div style="margin-top: 3rem; padding-top: 1.5rem; border-top: 1px solid #e5e7eb;">
                            <div class="row">
                                <div class="col">
                                    <p><strong>Completion Date:</strong><br>
                                        <?php echo date('F d, Y', strtotime($selected_certificate['completion_date'])); ?></p>
                                </div>
                                <div class="col">
                                    <p><strong>Certificate ID:</strong><br>
                                        <?php echo htmlspecialchars($selected_certificate['certificate_id']); ?></p>
                                </div>
                            </div>
                        </div>

                        <!-- Signature Area -->
                        <div style="margin-top: 2rem; padding-top: 1rem; border-top: 1px dashed #d1d5db;">
                            <div class="row">
                                <div class="col text-right">
                                    <p style="margin-bottom: 0.5rem;">_________________________</p>
                                    <p style="color: #6b7280; font-size: 0.9rem;">E-Learning Platform Director</p>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Action Buttons -->
                    <div class="row mt-4">
                        <div class="col">
                            <button onclick="printCertificate()" class="btn btn-primary btn-block">
                                <i class="fas fa-print"></i> Print Certificate
                            </button>
                        </div>
                        <div class="col">
                            <a href="certificates.php" class="btn btn-secondary btn-block">
                                <i class="fas fa-times"></i> Close Preview
                            </a>
                        </div>
                    </div>
                </div>
            </div>
        <?php endif; ?>

        <div class="row">
            <!-- Left Column: Available Certificates -->
            <div class="col">
                <!-- My Certificates -->
                <div class="card mb-4">
                    <div class="card-header">
                        <h3><i class="fas fa-award text-success"></i> My Certificates (<?php echo $total_certificates; ?>)</h3>
                    </div>
                    <div class="p-3">
                        <?php if ($total_certificates > 0): ?>
                            <div class="table-responsive">
                                <table class="table">
                                    <thead>
                                        <tr>
                                            <th>Certificate ID</th>
                                            <th>Course</th>
                                            <th>Quiz Score</th>
                                            <th>Completion Date</th>
                                            <th>Actions</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php foreach ($certificates as $certificate): ?>
                                            <tr>
                                                <td>
                                                    <code style="font-size: 0.8rem;"><?php echo substr($certificate['certificate_id'], 0, 15) . '...'; ?></code>
                                                </td>
                                                <td>
                                                    <strong><?php echo htmlspecialchars($certificate['course_title']); ?></strong><br>
                                                    <small class="text-secondary">Instructor: <?php echo htmlspecialchars($certificate['instructor_name']); ?></small>
                                                </td>
                                                <td>
                                                    <span class="badge <?php echo $certificate['quiz_score'] >= 80 ? 'badge-success' : ($certificate['quiz_score'] >= 70 ? 'badge-warning' : 'badge-info'); ?>">
                                                        <?php echo isset($certificate['quiz_score']) ? $certificate['quiz_score'] . '%' : 'N/A'; ?>
                                                    </span>
                                                </td>
                                                <td>
                                                    <?php echo date('M d, Y', strtotime($certificate['completion_date'])); ?>
                                                </td>

                                                <td>
                                                    <!-- View/Download buttons remain the same -->
                                                </td>
                                            </tr>
                                        <?php endforeach; ?>
                                    </tbody>
                                </table>
                            </div>
                        <?php else: ?>
                            <div class="text-center p-4">
                                <div style="font-size: 4rem; color: #d1d5db;">
                                    <i class="fas fa-certificate"></i>
                                </div>
                                <h4 class="mt-3">No Certificates Yet</h4>
                                <p class="text-secondary">Complete courses to earn certificates!</p>
                                <a href="#generate-certificate" class="btn btn-primary mt-2">
                                    <i class="fas fa-plus-circle"></i> Generate Sample Certificate
                                </a>
                            </div>
                        <?php endif; ?>
                    </div>
                </div>

                <!-- Certificate Stats -->
                <div class="card">
                    <div class="card-header">
                        <h3><i class="fas fa-chart-pie text-info"></i> Certificate Statistics</h3>
                    </div>
                    <div class="p-3">
                        <div class="row text-center">
                            <div class="col">
                                <div class="card" style="background: linear-gradient(135deg, rgba(16, 185, 129, 0.1) 0%, rgba(16, 185, 129, 0.05) 100%);">
                                    <h2 style="color: #10b981;"><?php echo $total_certificates; ?></h2>
                                    <p class="text-secondary">Total Certificates</p>
                                </div>
                            </div>
                            <div class="col">
                                <div class="card" style="background: linear-gradient(135deg, rgba(245, 158, 11, 0.1) 0%, rgba(245, 158, 11, 0.05) 100%);">
                                    <h2 style="color: #f59e0b;"><?php echo count($enrolled_courses); ?></h2>
                                    <p class="text-secondary">Enrolled Courses</p>
                                </div>
                            </div>
                            <div class="col">
                                <div class="card" style="background: linear-gradient(135deg, rgba(239, 68, 68, 0.1) 0%, rgba(239, 68, 68, 0.05) 100%);">
                                    <h2 style="color: #ef4444;">
                                        <?php echo count($enrolled_courses) > 0 ? round(($total_certificates / count($enrolled_courses)) * 100) : 0; ?>%
                                    </h2>
                                    <p class="text-secondary">Completion Rate</p>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Right Column: Generate Certificate -->
            <div class="col">
                <!-- Generate Certificate Form -->
                <div class="card mb-4" id="generate-certificate">
                    <div class="card-header">
                        <h3><i class="fas fa-plus-circle text-primary"></i> Generate Certificate</h3>
                    </div>
                    <div class="p-3">
                        <p class="text-secondary mb-3">
                            Select a completed course to generate a certificate. Certificates are official documents of course completion.
                        </p>

                        <form method="POST" action="">
                            <div class="form-group">
                                <label for="course_id" class="form-label">Select Course</label>
                                <select id="course_id" name="course_id" class="form-control" required>
                                    <option value="">-- Select a course --</option>
                                    <?php if (!empty($enrolled_courses)): ?>
                                        <?php foreach ($enrolled_courses as $course):
                                            // Check 1: Already has certificate
                                            $has_certificate = false;
                                            foreach ($certificates as $cert) {
                                                if ($cert['course_id'] == $course['id']) {
                                                    $has_certificate = true;
                                                    break;
                                                }
                                            }

                                            // Check 2: Has passed the quiz
                                            $has_passed_quiz = false;
                                            $quiz_score = 0;
                                            try {
                                                $stmt = $pdo->prepare("SELECT up.passed, up.best_score 
                                  FROM user_quiz_progress up
                                  JOIN quizzes q ON up.quiz_id = q.id
                                  WHERE up.user_id = ? AND up.course_id = ? AND up.passed = TRUE");
                                                $stmt->execute([$user_id, $course['id']]);
                                                $quiz_result = $stmt->fetch();
                                                $has_passed_quiz = ($quiz_result != false);
                                                $quiz_score = $quiz_result ? $quiz_result['best_score'] : 0;
                                            } catch (PDOException $e) {
                                                // Skip error for display purposes
                                            }

                                            // Only show option if: no certificate yet AND quiz is passed
                                            $can_generate = (!$has_certificate && $has_passed_quiz);
                                        ?>
                                            <option value="<?php echo $course['id']; ?>"
                                                <?php echo !$can_generate ? 'disabled' : ''; ?>
                                                data-score="<?php echo $quiz_score; ?>">

                                                <?php echo htmlspecialchars($course['title']); ?>

                                                <?php if ($has_certificate): ?>
                                                    (✓ Certificate already generated)
                                                <?php elseif (!$has_passed_quiz): ?>
                                                    (✗ Quiz not passed - Score needed: <?php echo $quiz_score; ?>%)
                                                <?php else: ?>
                                                    (✓ Quiz passed: <?php echo $quiz_score; ?>%)
                                                <?php endif; ?>
                                            </option>
                                        <?php endforeach; ?>
                                    <?php endif; ?>
                                </select>
                            </div>

                            <div class="alert alert-info">
                                <i class="fas fa-info-circle"></i>
                                <strong>Note:</strong> Certificates can only be generated once per course.
                                Make sure you have completed the course requirements.
                            </div>

                            <button type="submit" name="generate_certificate" class="btn btn-primary btn-block">
                                <i class="fas fa-certificate"></i> Generate Certificate
                            </button>
                        </form>
                    </div>
                </div>

                <!-- How It Works -->
                <div class="card mb-4">
                    <div class="card-header">
                        <h3><i class="fas fa-question-circle text-warning"></i> How Certificates Work</h3>
                    </div>
                    <div class="p-3">
                        <ol class="text-secondary">
                            <li><strong>Enroll in a course</strong> from the dashboard</li>
                            <li><strong>Complete all course requirements</strong> (watch videos, complete assignments)</li>
                            <li><strong>Generate certificate</strong> once course is marked as completed</li>
                            <li><strong>View/Download</strong> your certificate anytime</li>
                            <li><strong>Share</strong> your achievement on professional networks</li>
                        </ol>

                        <div class="alert alert-success mt-3">
                            <i class="fas fa-shield-alt"></i>
                            <strong>Verification:</strong> All certificates include a unique ID that can be verified
                            through our platform for authenticity.
                        </div>
                    </div>
                </div>

                <!-- Quick Links -->
                <div class="card">
                    <div class="card-header">
                        <h3><i class="fas fa-link text-success"></i> Quick Links</h3>
                    </div>
                    <div class="p-3">
                        <div class="row">
                            <div class="col">
                                <a href="student_dashboard.php" class="btn btn-outline btn-block">
                                    <i class="fas fa-home"></i> Dashboard
                                </a>
                            </div>
                            <div class="col">
                                <a href="my_courses.php" class="btn btn-outline btn-block">
                                    <i class="fas fa-book-open"></i> My Courses
                                </a>
                            </div>
                        </div>
                        <div class="row mt-2">
                            <div class="col">
                                <a href="profile.php" class="btn btn-outline btn-block">
                                    <i class="fas fa-user-circle"></i> Profile
                                </a>
                            </div>
                            <div class="col">
                                <button onclick="alert('Contact support@elearn.com for certificate verification')"
                                    class="btn btn-outline btn-block">
                                    <i class="fas fa-question-circle"></i> Help
                                </button>
                            </div>
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
                <p>© <?php echo date('Y'); ?> E-Learning Platform. Certificate Management.</p>
                <p class="text-secondary">
                    <i class="fas fa-user-graduate"></i>
                    Student: <?php echo htmlspecialchars($full_name); ?> |
                    Total Certificates: <?php echo $total_certificates; ?>
                </p>
            </div>
        </div>
    </footer>

    <!-- JavaScript -->
    <script>
        // Initialize when page is fully loaded
        function initCertificates() {
            autoHideAlerts();
            setupPrintFunction();
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

        // Print certificate function
        function printCertificate() {
            window.print();
        }

        // Simulate certificate download
        function downloadCertificate(certId, courseTitle) {
            alert('Downloading certificate: ' + courseTitle + '\nCertificate ID: ' + certId + '\n\n(In a real system, this would generate a PDF download)');

            // In a real system, you would:
            // 1. Make an AJAX call to generate PDF
            // 2. Return PDF download link
            // 3. Trigger download

            // For demo purposes, we'll show a success message
            var alertDiv = document.createElement('div');
            alertDiv.className = 'alert alert-success fade-in';
            alertDiv.innerHTML = '<i class="fas fa-check-circle"></i> Certificate download started for: ' + courseTitle;
            document.querySelector('.container').prepend(alertDiv);

            // Auto-hide the new alert
            setTimeout(function() {
                alertDiv.style.opacity = '0';
                setTimeout(function() {
                    alertDiv.style.display = 'none';
                }, 300);
            }, 3000);
        }

        // Initialize when DOM is ready
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', initCertificates);
        } else {
            initCertificates();
        }
    </script>

    <style>
        /* Certificate specific styles */
        @media print {

            .navbar,
            .footer,
            .card-header,
            .btn,
            #generate-certificate,
            .alert {
                display: none !important;
            }

            .container {
                padding: 0 !important;
                margin: 0 !important;
                max-width: 100% !important;
            }

            .card {
                border: none !important;
                box-shadow: none !important;
                margin: 0 !important;
                padding: 0 !important;
            }
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

        .btn-group {
            display: flex;
            gap: 0.25rem;
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