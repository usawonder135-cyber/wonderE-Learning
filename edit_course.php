<?php
// edit_course.php - Edit Course Page
session_start();

// Check if user is logged in and is admin
if (!isset($_SESSION['user_id'], $_SESSION['role']) || $_SESSION['role'] !== 'admin') {
    header('Location: login.php');
    exit();
}

// Include database connection
require_once 'db_conn.php';

// Initialize variables
$course_id = 0;
$course = null;
$title = $description = $video_url = $thumbnail_path = '';
$error_message = '';
$success_message = '';

// Get course ID from URL and validate
if (isset($_GET['id']) && is_numeric($_GET['id'])) {
    $course_id = intval($_GET['id']);
    
    // Fetch course details
    try {
        $stmt = $pdo->prepare("SELECT c.*, u.full_name as creator 
                               FROM courses c 
                               JOIN users u ON c.created_by = u.id 
                               WHERE c.id = ?");
        $stmt->execute([$course_id]);
        $course = $stmt->fetch();
        
        if (!$course) {
            $error_message = "Course not found.";
        } else {
            // Pre-fill form fields
            $title = $course['title'];
            $description = $course['description'];
            $video_url = $course['video_url'];
            $thumbnail_path = $course['thumbnail_image'];
            $created_by = $course['created_by'];
            $creator_name = $course['creator'];
        }
    } catch (PDOException $e) {
        error_log("Error fetching course: " . $e->getMessage());
        $error_message = "Unable to load course details.";
    }
} else {
    $error_message = "Invalid course ID.";
}

// Handle form submission
if ($_SERVER["REQUEST_METHOD"] == "POST" && $course) {
    // Sanitize and validate inputs
    $title = trim($_POST['title'] ?? '');
    $description = trim($_POST['description'] ?? '');
    $video_url = trim($_POST['video_url'] ?? '');
    
    // Validation
    $errors = [];
    
    if (empty($title)) {
        $errors[] = "Course title is required.";
    } elseif (strlen($title) < 3) {
        $errors[] = "Course title must be at least 3 characters.";
    }
    
    if (empty($description)) {
        $errors[] = "Course description is required.";
    }
    
    // Validate video URL format if provided
    if (!empty($video_url) && !filter_var($video_url, FILTER_VALIDATE_URL)) {
        $errors[] = "Please enter a valid URL for the video.";
    }
    
    // Handle file upload
    $new_thumbnail_path = $thumbnail_path; // Keep existing by default
    $file_uploaded = false;
    
    if (isset($_FILES['thumbnail']) && $_FILES['thumbnail']['error'] == 0) {
        $allowed_types = ['image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp'];
        $max_size = 5 * 1024 * 1024; // 5MB
        $file_type = $_FILES['thumbnail']['type'];
        $file_size = $_FILES['thumbnail']['size'];
        
        // Check file type
        if (!in_array($file_type, $allowed_types)) {
            $errors[] = "Only JPG, JPEG, PNG, GIF, and WebP files are allowed.";
        }
        
        // Check file size
        if ($file_size > $max_size) {
            $errors[] = "File size must be less than 5MB.";
        }
        
        if (empty($errors)) {
            // Generate unique filename
            $file_extension = pathinfo($_FILES['thumbnail']['name'], PATHINFO_EXTENSION);
            $new_filename = 'thumbnail_' . time() . '_' . uniqid() . '.' . strtolower($file_extension);
            $target_file = 'uploads/' . $new_filename;
            
            // Create uploads directory if it doesn't exist
            if (!file_exists('uploads')) {
                mkdir('uploads', 0755, true);
            }
            
            // Move uploaded file
            if (move_uploaded_file($_FILES['thumbnail']['tmp_name'], $target_file)) {
                $new_thumbnail_path = $target_file;
                $file_uploaded = true;
                
                // Delete old thumbnail if it exists and is different from new one
                if (!empty($thumbnail_path) && $thumbnail_path !== $new_thumbnail_path && file_exists($thumbnail_path)) {
                    unlink($thumbnail_path);
                }
            } else {
                $errors[] = "Failed to upload thumbnail image.";
            }
        }
    }
    
    // If no errors, update database
    if (empty($errors)) {
        try {
            // Prepare SQL statement - REMOVED updated_at column
            $stmt = $pdo->prepare("UPDATE courses 
                                   SET title = :title, 
                                       description = :description, 
                                       thumbnail_image = :thumbnail, 
                                       video_url = :video_url
                                   WHERE id = :id");
            
            // Bind parameters
            $stmt->bindParam(':title', $title);
            $stmt->bindParam(':description', $description);
            $stmt->bindParam(':thumbnail', $new_thumbnail_path);
            $stmt->bindParam(':video_url', $video_url);
            $stmt->bindParam(':id', $course_id, PDO::PARAM_INT);
            
            // Execute query
            if ($stmt->execute()) {
                // Update local thumbnail path if changed
                if ($file_uploaded) {
                    $thumbnail_path = $new_thumbnail_path;
                }
                
                // Redirect with success message
                header('Location: admin_dashboard.php?msg=CourseUpdated');
                exit();
            } else {
                $error_message = "Failed to update course. Please try again.";
            }
            
        } catch (PDOException $e) {
            $error_message = "Database error: " . $e->getMessage();
            error_log("Course update error: " . $e->getMessage());
            
            // If there was a database error and we uploaded a new file, delete it
            if ($file_uploaded && file_exists($new_thumbnail_path)) {
                unlink($new_thumbnail_path);
            }
        }
    } else {
        // Combine errors into a single message
        $error_message = implode("<br>", $errors);
    }
}
?>
<?php
// In edit_course.php, after fetching course details, add:

// Check if course has quiz
try {
    $stmt = $pdo->prepare("SELECT * FROM quizzes WHERE course_id = ? AND is_active = TRUE");
    $stmt->execute([$course_id]);
    $quiz = $stmt->fetch();
    
    $has_quiz = ($quiz !== false);
} catch (PDOException $e) {
    $has_quiz = false;
}
?>

<!-- Add this in the course info display area -->
<div class="alert alert-info mt-3">
    <i class="fas fa-question-circle"></i>
    <strong>Quiz Status:</strong>
    <?php if ($has_quiz): ?>
        This course has an active quiz. 
        <a href="add_quiz_questions.php?quiz_id=<?php echo $quiz['id']; ?>" class="btn btn-sm btn-info ml-2">
            <i class="fas fa-edit"></i> Edit Quiz
        </a>
    <?php else: ?>
        This course doesn't have a quiz yet.
        <a href="add_quiz.php?course_id=<?php echo $course_id; ?>" class="btn btn-sm btn-success ml-2">
            <i class="fas fa-plus"></i> Add Quiz
        </a>
    <?php endif; ?>
</div>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Edit Course - E-Learning Admin</title>
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
                <li><a href="admin_dashboard.php" class="nav-link"><i class="fas fa-tachometer-alt"></i> Dashboard</a></li>
                <li><a href="add_course.php" class="nav-link"><i class="fas fa-plus-circle"></i> Add Course</a></li>
                <li><a href="#" class="nav-link"><i class="fas fa-users"></i> Students</a></li>
                <li><a href="logout.php" class="btn btn-danger btn-sm"><i class="fas fa-sign-out-alt"></i> Logout</a></li>
            </ul>
        </div>
    </nav>

    <!-- Main Content -->
    <div class="container mt-4">
        <div class="row">
            <div class="col" style="max-width: 800px; margin: 0 auto;">
                <div class="card">
                    <!-- Header -->
                    <div class="card-header">
                        <h1><i class="fas fa-edit text-primary"></i> Edit Course</h1>
                        <p class="text-secondary">Update course information</p>
                    </div>
                    
                    <!-- Display Error Message -->
                    <?php if ($error_message && !$course): ?>
                        <div class="alert alert-danger">
                            <i class="fas fa-exclamation-circle"></i> <?php echo $error_message; ?>
                            <div class="mt-3">
                                <a href="admin_dashboard.php" class="btn btn-primary">
                                    <i class="fas fa-arrow-left"></i> Back to Dashboard
                                </a>
                            </div>
                        </div>
                    <?php else: ?>
                        <!-- Display Course Info -->
                        <?php if ($course): ?>
                            <div class="alert alert-info">
                                <i class="fas fa-info-circle"></i> 
                                Course ID: #<?php echo $course_id; ?> | 
                                Created by: <?php echo htmlspecialchars($creator_name); ?> | 
                                Created on: <?php echo date('M d, Y', strtotime($course['created_at'])); ?>
                            </div>
                        <?php endif; ?>
                        
                        <!-- Display Error Message (if any) -->
                        <?php if ($error_message): ?>
                            <div class="alert alert-danger">
                                <i class="fas fa-exclamation-circle"></i> <?php echo $error_message; ?>
                            </div>
                        <?php endif; ?>
                        
                        <!-- Course Form -->
                        <form method="POST" action="<?php echo htmlspecialchars($_SERVER['PHP_SELF']) . '?id=' . $course_id; ?>" enctype="multipart/form-data">
                            <!-- Title -->
                            <div class="form-group">
                                <label for="title" class="form-label">
                                    <i class="fas fa-heading"></i> Course Title *
                                </label>
                                <input 
                                    type="text" 
                                    id="title" 
                                    name="title" 
                                    class="form-control" 
                                    placeholder="Enter course title"
                                    value="<?php echo htmlspecialchars($title); ?>"
                                    required
                                    maxlength="200"
                                >
                                <small class="form-text">Maximum 200 characters</small>
                            </div>
                            
                            <!-- Description -->
                            <div class="form-group">
                                <label for="description" class="form-label">
                                    <i class="fas fa-align-left"></i> Course Description *
                                </label>
                                <textarea 
                                    id="description" 
                                    name="description" 
                                    class="form-control" 
                                    placeholder="Enter detailed course description"
                                    rows="5"
                                    required
                                ><?php echo htmlspecialchars($description); ?></textarea>
                                <small class="form-text">Describe what students will learn in this course</small>
                            </div>
                            
                            <!-- Video URL -->
                            <div class="form-group">
                                <label for="video_url" class="form-label">
                                    <i class="fas fa-video"></i> Video URL
                                </label>
                                <input 
                                    type="url" 
                                    id="video_url" 
                                    name="video_url" 
                                    class="form-control" 
                                    placeholder="https://example.com/video.mp4"
                                    value="<?php echo htmlspecialchars($video_url); ?>"
                                >
                                <small class="form-text">Enter the URL of the course video (YouTube, Vimeo, or direct video link)</small>
                            </div>
                            
                            <!-- Thumbnail Image -->
                            <div class="form-group">
                                <label for="thumbnail" class="form-label">
                                    <i class="fas fa-image"></i> Thumbnail Image
                                </label>
                                
                                <!-- Current Thumbnail Preview -->
                                <?php if (!empty($thumbnail_path) && file_exists($thumbnail_path)): ?>
                                    <div class="mb-3">
                                        <p class="text-secondary">Current Thumbnail:</p>
                                        <img src="<?php echo htmlspecialchars($thumbnail_path); ?>" 
                                             alt="Current thumbnail" 
                                             style="max-width: 200px; max-height: 150px; border-radius: 8px; border: 2px solid #e5e7eb;">
                                        <small class="d-block text-secondary mt-1">
                                            <i class="fas fa-info-circle"></i> Leave empty to keep current image
                                        </small>
                                    </div>
                                <?php else: ?>
                                    <div class="mb-3">
                                        <p class="text-secondary">No thumbnail currently set.</p>
                                    </div>
                                <?php endif; ?>
                                
                                <!-- New Thumbnail Preview -->
                                <div id="new-thumbnail-preview" class="mb-3" style="display: none;">
                                    <p class="text-secondary">New Thumbnail Preview:</p>
                                    <img id="preview-image" src="" alt="Preview" style="max-width: 200px; max-height: 150px; border-radius: 8px;">
                                </div>
                                
                                <!-- File Input -->
                                <div class="file-upload">
                                    <input 
                                        type="file" 
                                        id="thumbnail" 
                                        name="thumbnail" 
                                        class="form-control" 
                                        accept="image/*"
                                        onchange="previewImage(event)"
                                    >
                                </div>
                                <small class="form-text">
                                    Upload a new thumbnail image (JPG, PNG, GIF, WebP). Max size: 5MB. Leave empty to keep current image.
                                </small>
                            </div>
                            
                            <!-- Form Actions -->
<div class="row mt-4">
    <div class="col">
        <button type="submit" class="btn btn-primary btn-block btn-lg">
            <i class="fas fa-save"></i> Update Course
        </button>
    </div>
    <div class="col">
        <a href="add_quiz.php?course_id=<?php echo $course_id; ?>" class="btn btn-success btn-block btn-lg">
            <i class="fas fa-question-circle"></i> Add Quiz
        </a>
    </div>
    <div class="col">
        <a href="admin_dashboard.php" class="btn btn-secondary btn-block btn-lg">
            <i class="fas fa-times"></i> Cancel
        </a>
    </div>
    <div class="col">
        <a href="delete_course.php?id=<?php echo $course_id; ?>" 
           class="btn btn-danger btn-block btn-lg"
           onclick="return confirm('Are you sure you want to delete this course? This action cannot be undone.')">
            <i class="fas fa-trash"></i> Delete Course
        </a>
    </div>
</div>
                        <!-- Instructions -->
                        <div class="card mt-4" style="background-color: rgba(37, 99, 235, 0.05);">
                            <div class="card-header">
                                <h4><i class="fas fa-info-circle text-primary"></i> Instructions</h4>
                            </div>
                            <div class="p-3">
                                <ol class="text-secondary">
                                    <li>Fields marked with * are required</li>
                                    <li>To change the thumbnail, select a new image file</li>
                                    <li>Leave the thumbnail field empty to keep the current image</li>
                                    <li>Old thumbnail will be automatically deleted if replaced</li>
                                    <li>Video URL can be a YouTube link, Vimeo link, or direct video file URL</li>
                                    <li>After updating, the course will reflect changes immediately</li>
                                </ol>
                            </div>
                        </div>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    </div>

    <!-- Footer -->
    <footer class="footer mt-5">
        <div class="container">
            <div class="text-center">
                <p>© <?php echo date('Y'); ?> E-Learning Platform. Admin Panel.</p>
                <p class="text-secondary">
                    <i class="fas fa-user-tie"></i> 
                    Logged in as: <?php echo htmlspecialchars($_SESSION['full_name'] ?? 'Admin'); ?>
                </p>
            </div>
        </div>
    </footer>

    <!-- JavaScript for Image Preview -->
    <script>
        function previewImage(event) {
            const input = event.target;
            const preview = document.getElementById('new-thumbnail-preview');
            const previewImage = document.getElementById('preview-image');
            
            if (input.files && input.files[0]) {
                const reader = new FileReader();
                
                reader.onload = function(e) {
                    previewImage.src = e.target.result;
                    preview.style.display = 'block';
                };
                
                reader.readAsDataURL(input.files[0]);
            } else {
                preview.style.display = 'none';
                previewImage.src = '';
            }
        }
        
        // Form validation
        document.addEventListener('DOMContentLoaded', function() {
            const form = document.querySelector('form');
            const titleInput = document.getElementById('title');
            const descriptionInput = document.getElementById('description');
            const fileInput = document.getElementById('thumbnail');
            
            // Validate title length
            titleInput.addEventListener('input', function() {
                if (this.value.length < 3) {
                    this.style.borderColor = '#ef4444';
                } else {
                    this.style.borderColor = '#e5e7eb';
                }
            });
            
            // Validate file size on change
            fileInput.addEventListener('change', function() {
                const maxSize = 5 * 1024 * 1024; // 5MB
                if (this.files[0] && this.files[0].size > maxSize) {
                    alert('File size exceeds 5MB limit. Please choose a smaller file.');
                    this.value = '';
                    document.getElementById('new-thumbnail-preview').style.display = 'none';
                }
            });
            
            // Form submission validation
            form.addEventListener('submit', function(e) {
                let isValid = true;
                
                // Check required fields
                if (titleInput.value.trim().length < 3) {
                    alert('Course title must be at least 3 characters.');
                    titleInput.focus();
                    isValid = false;
                }
                
                if (descriptionInput.value.trim().length === 0) {
                    alert('Please enter a course description.');
                    descriptionInput.focus();
                    isValid = false;
                }
                
                if (!isValid) {
                    e.preventDefault();
                }
            });
        });
    </script>
    
    <style>
        /* Custom file upload styling */
        .file-upload {
            position: relative;
            overflow: hidden;
        }
        
        .file-upload input[type="file"] {
            position: absolute;
            top: 0;
            right: 0;
            margin: 0;
            padding: 0;
            font-size: 20px;
            cursor: pointer;
            opacity: 0;
            filter: alpha(opacity=0);
            width: 100%;
            height: 100%;
        }
        
        .file-upload .form-control {
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid rgba(255, 255, 255, 0.2);
            padding: 0.875rem 1rem;
            cursor: pointer;
        }
        
        /* Make form responsive */
        @media (max-width: 768px) {
            .row {
                flex-direction: column;
            }
            
            .col {
                width: 100%;
                margin-bottom: 1rem;
            }
        }
    </style>
</body>
</html>