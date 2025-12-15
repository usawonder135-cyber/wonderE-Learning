<?php
// add_course.php - Admin: Add New Course
session_start();

// Check if user is logged in and is admin
if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'admin') {
    header('Location: login.php');
    exit();
}

// Include database connection
require_once 'db_conn.php';

// Initialize variables
$title = $description = $video_url = '';
$error_message = '';
$success_message = '';
$thumbnail_path = '';

// Create uploads directory if it doesn't exist
if (!file_exists('uploads')) {
    mkdir('uploads', 0755, true);
}

// Handle form submission
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Sanitize and validate inputs
    $title = trim($_POST['title']);
    $description = trim($_POST['description']);
    $video_url = trim($_POST['video_url']);
    $created_by = $_SESSION['user_id'];
    
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
    
    // Validate video URL format
    if (!empty($video_url) && !filter_var($video_url, FILTER_VALIDATE_URL)) {
        $errors[] = "Please enter a valid URL for the video.";
    }
    
    // Handle file upload
    $thumbnail_name = '';
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
            $thumbnail_name = 'thumbnail_' . time() . '_' . uniqid() . '.' . strtolower($file_extension);
            $target_file = 'uploads/' . $thumbnail_name;
            
            // Move uploaded file
            if (move_uploaded_file($_FILES['thumbnail']['tmp_name'], $target_file)) {
                $thumbnail_path = $target_file;
            } else {
                $errors[] = "Failed to upload thumbnail image.";
            }
        }
    } else {
        // If no file uploaded, set default thumbnail
        $thumbnail_path = '';
    }
    
    // If no errors, insert into database
    if (empty($errors)) {
        try {
            // Prepare SQL statement
            $stmt = $pdo->prepare("INSERT INTO courses (title, description, thumbnail_image, video_url, created_by, created_at) 
                                   VALUES (:title, :description, :thumbnail, :video_url, :created_by, NOW())");
            
            // Bind parameters
            $stmt->bindParam(':title', $title);
            $stmt->bindParam(':description', $description);
            $stmt->bindParam(':thumbnail', $thumbnail_path);
            $stmt->bindParam(':video_url', $video_url);
            $stmt->bindParam(':created_by', $created_by, PDO::PARAM_INT);
            
            // Execute query
            if ($stmt->execute()) {
                // Redirect with success message
                header('Location: admin_dashboard.php?msg=CourseAdded');
                exit();
            } else {
                $error_message = "Failed to add course. Please try again.";
            }
            
        } catch (PDOException $e) {
            $error_message = "Database error: " . $e->getMessage();
            // If there was a database error, delete the uploaded file
            if ($thumbnail_path && file_exists($thumbnail_path)) {
                unlink($thumbnail_path);
            }
        }
    } else {
        // Combine errors into a single message
        $error_message = implode("<br>", $errors);
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Add New Course - E-Learning Admin</title>
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
                <li><a href="add_course.php" class="nav-link active"><i class="fas fa-plus-circle"></i> Add Course</a></li>
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
                        <h1><i class="fas fa-plus-circle text-primary"></i> Add New Course</h1>
                        <p class="text-secondary">Create a new course for your e-learning platform</p>
                    </div>
                    
                    <!-- Display Error Message -->
                    <?php if ($error_message): ?>
                        <div class="alert alert-danger">
                            <i class="fas fa-exclamation-circle"></i> <?php echo $error_message; ?>
                        </div>
                    <?php endif; ?>
                    
                    <!-- Display Success Message from URL parameter -->
                    <?php if (isset($_GET['msg']) && $_GET['msg'] == 'CourseAdded'): ?>
                        <div class="alert alert-success">
                            <i class="fas fa-check-circle"></i> Course added successfully!
                        </div>
                    <?php endif; ?>
                    
                    <!-- Course Form -->
                    <form method="POST" action="<?php echo htmlspecialchars($_SERVER['PHP_SELF']); ?>" enctype="multipart/form-data">
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
                            
                            <!-- File Upload Preview -->
                            <div id="thumbnail-preview" class="mb-3" style="display: none;">
                                <img id="preview-image" src="" alt="Preview" style="max-width: 200px; max-height: 150px; border-radius: 8px;">
                            </div>
                            
                            <!-- File Input with Custom Styling -->
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
                                Upload a thumbnail image (JPG, PNG, GIF, WebP). Max size: 5MB.
                                <?php if (isset($_FILES['thumbnail']) && $_FILES['thumbnail']['error'] == 0): ?>
                                    <br><span class="text-success">✓ Image uploaded successfully</span>
                                <?php endif; ?>
                            </small>
                        </div>
                        
                        <!-- Form Actions -->
                        <div class="row mt-4">
                            <div class="col">
                                <button type="submit" class="btn btn-primary btn-block btn-lg">
                                    <i class="fas fa-save"></i> Create Course
                                </button>
                            </div>
                            <div class="col">
                                <a href="admin_dashboard.php" class="btn btn-secondary btn-block btn-lg">
                                    <i class="fas fa-arrow-left"></i> Cancel
                                </a>
                            </div>
                        </div>
                    </form>
                    
                    <!-- Instructions -->
                    <div class="card mt-4" style="background-color: rgba(37, 99, 235, 0.05);">
                        <div class="card-header">
                            <h4><i class="fas fa-info-circle text-primary"></i> Instructions</h4>
                        </div>
                        <div class="p-3">
                            <ol class="text-secondary">
                                <li>Fields marked with * are required</li>
                                <li>Course title should be clear and descriptive</li>
                                <li>Provide detailed description of course content</li>
                                <li>Video URL can be a YouTube link, Vimeo link, or direct video file URL</li>
                                <li>Thumbnail image is optional but recommended (optimal size: 1280x720px)</li>
                                <li>After creation, the course will appear in the dashboard</li>
                            </ol>
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
                <p>© <?php echo date('Y'); ?> E-Learning Platform. Admin Panel.</p>
                <p class="text-secondary">
                    <i class="fas fa-user-tie"></i> 
                    Logged in as: <?php echo htmlspecialchars($_SESSION['full_name']); ?>
                </p>
            </div>
        </div>
    </footer>

    <!-- JavaScript for Image Preview -->
    <script>
        function previewImage(event) {
            const input = event.target;
            const preview = document.getElementById('thumbnail-preview');
            const previewImage = document.getElementById('preview-image');
            
            if (input.files && input.files[0]) {
                const reader = new FileReader();
                
                reader.onload = function(e) {
                    previewImage.src = e.target.result;
                    preview.style.display = 'block';
                }
                
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
                    document.getElementById('thumbnail-preview').style.display = 'none';
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
        
        .file-upload .form-control::before {
            content: 'Choose file';
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