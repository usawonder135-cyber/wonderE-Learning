<?php
// search.php - Course Search and Filtering
session_start();

if (!isset($_SESSION['user_id'], $_SESSION['role']) || $_SESSION['role'] !== 'student') {
    header('Location: login.php');
    exit();
}

require_once 'db_conn.php';

$user_id = $_SESSION['user_id'];
$search_query = isset($_GET['q']) ? trim($_GET['q']) : '';
$category = isset($_GET['category']) ? $_GET['category'] : '';
$price_filter = isset($_GET['price']) ? $_GET['price'] : '';
$difficulty = isset($_GET['difficulty']) ? $_GET['difficulty'] : '';
$sort_by = isset($_GET['sort']) ? $_GET['sort'] : 'newest';

// Get enrolled course IDs
try {
    $stmt = $pdo->prepare("SELECT course_id FROM enrollments WHERE user_id = ?");
    $stmt->execute([$user_id]);
    $enrolled_course_ids = $stmt->fetchAll(PDO::FETCH_COLUMN, 0);
    $enrolled_course_ids = $enrolled_course_ids ?: [];
} catch (PDOException $e) {
    error_log("Search error: " . $e->getMessage());
    $enrolled_course_ids = [];
}

// Build search query
$sql = "SELECT 
    c.id as course_id,
    c.title,
    c.description,
    c.thumbnail_image,
    c.video_url,
    c.price,
    c.category,
    c.difficulty,
    c.rating,
    c.created_at,
    u.full_name as instructor_name
    FROM courses c
    JOIN users u ON c.created_by = u.id
    WHERE 1=1";
    
$params = [];
$types = '';

// Apply search filters
if (!empty($search_query)) {
    $sql .= " AND (c.title LIKE ? OR c.description LIKE ? OR u.full_name LIKE ?)";
    $search_term = "%$search_query%";
    $params[] = $search_term;
    $params[] = $search_term;
    $params[] = $search_term;
    $types .= 'sss';
}

if (!empty($category)) {
    $sql .= " AND c.category = ?";
    $params[] = $category;
    $types .= 's';
}

if (!empty($price_filter)) {
    if ($price_filter === 'free') {
        $sql .= " AND c.price = 0";
    } elseif ($price_filter === 'paid') {
        $sql .= " AND c.price > 0";
    }
}

if (!empty($difficulty)) {
    $sql .= " AND c.difficulty = ?";
    $params[] = $difficulty;
    $types .= 's';
}

// Apply sorting
switch ($sort_by) {
    case 'newest':
        $sql .= " ORDER BY c.created_at DESC";
        break;
    case 'price_low':
        $sql .= " ORDER BY c.price ASC";
        break;
    case 'price_high':
        $sql .= " ORDER BY c.price DESC";
        break;
    case 'rating':
        $sql .= " ORDER BY c.rating DESC";
        break;
    default:
        $sql .= " ORDER BY c.created_at DESC";
}

try {
    $stmt = $pdo->prepare($sql);
    if (!empty($params)) {
        $stmt->execute($params);
    } else {
        $stmt->execute();
    }
    $courses = $stmt->fetchAll();
    
    // Get unique categories for filter
    $stmt = $pdo->query("SELECT DISTINCT category FROM courses WHERE category IS NOT NULL AND category != '' ORDER BY category");
    $categories = $stmt->fetchAll(PDO::FETCH_COLUMN, 0);
    
} catch (PDOException $e) {
    error_log("Search query error: " . $e->getMessage());
    $courses = [];
    $categories = [];
    $error_message = "Unable to perform search. Please try again.";
}

// Get search statistics
$total_courses = count($courses);
$free_count = 0;
$paid_count = 0;
foreach ($courses as $course) {
    if ($course['price'] == 0) {
        $free_count++;
    } else {
        $paid_count++;
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Search Courses - E-Learning Platform</title>
    <link rel="stylesheet" href="style.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
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
                <li><a href="search.php" class="nav-link active"><i class="fas fa-search"></i> Search</a></li>
                <li><a href="my_courses.php" class="nav-link"><i class="fas fa-book-open"></i> My Courses</a></li>
                <li><a href="logout.php" class="btn btn-danger btn-sm"><i class="fas fa-sign-out-alt"></i> Logout</a></li>
            </ul>
        </div>
    </nav>

    <div class="container mt-4">
        <!-- Search Header -->
        <div class="card mb-4">
            <div class="card-body">
                <h1 class="mb-3"><i class="fas fa-search"></i> Find Your Perfect Course</h1>
                
                <!-- Search Form -->
                <form method="GET" action="search.php" class="mb-4">
                    <div class="row">
                        <div class="col">
                            <div class="input-group">
                                <div class="input-group-prepend">
                                    <span class="input-group-text"><i class="fas fa-search"></i></span>
                                </div>
                                <input type="text" name="q" class="form-control" 
                                       placeholder="Search courses, instructors, or keywords..."
                                       value="<?php echo htmlspecialchars($search_query); ?>">
                            </div>
                        </div>
                        <div class="col-auto">
                            <button type="submit" class="btn btn-primary">
                                <i class="fas fa-search"></i> Search
                            </button>
                            <a href="search.php" class="btn btn-secondary">Clear</a>
                        </div>
                    </div>
                </form>
                
                <!-- Filter Section -->
                <div class="row">
                    <div class="col">
                        <form method="GET" action="search.php" id="filter-form">
                            <input type="hidden" name="q" value="<?php echo htmlspecialchars($search_query); ?>">
                            
                            <div class="row">
                                <div class="col">
                                    <label>Category:</label>
                                    <select name="category" class="form-control" onchange="document.getElementById('filter-form').submit()">
                                        <option value="">All Categories</option>
                                        <?php foreach ($categories as $cat): ?>
                                        <option value="<?php echo htmlspecialchars($cat); ?>" 
                                            <?php echo $category == $cat ? 'selected' : ''; ?>>
                                            <?php echo htmlspecialchars($cat); ?>
                                        </option>
                                        <?php endforeach; ?>
                                    </select>
                                </div>
                                
                                <div class="col">
                                    <label>Price:</label>
                                    <select name="price" class="form-control" onchange="document.getElementById('filter-form').submit()">
                                        <option value="">All Prices</option>
                                        <option value="free" <?php echo $price_filter == 'free' ? 'selected' : ''; ?>>Free Only</option>
                                        <option value="paid" <?php echo $price_filter == 'paid' ? 'selected' : ''; ?>>Paid Only</option>
                                    </select>
                                </div>
                                
                                <div class="col">
                                    <label>Difficulty:</label>
                                    <select name="difficulty" class="form-control" onchange="document.getElementById('filter-form').submit()">
                                        <option value="">All Levels</option>
                                        <option value="beginner" <?php echo $difficulty == 'beginner' ? 'selected' : ''; ?>>Beginner</option>
                                        <option value="intermediate" <?php echo $difficulty == 'intermediate' ? 'selected' : ''; ?>>Intermediate</option>
                                        <option value="advanced" <?php echo $difficulty == 'advanced' ? 'selected' : ''; ?>>Advanced</option>
                                    </select>
                                </div>
                                
                                <div class="col">
                                    <label>Sort By:</label>
                                    <select name="sort" class="form-control" onchange="document.getElementById('filter-form').submit()">
                                        <option value="newest" <?php echo $sort_by == 'newest' ? 'selected' : ''; ?>>Newest First</option>
                                        <option value="rating" <?php echo $sort_by == 'rating' ? 'selected' : ''; ?>>Highest Rated</option>
                                        <option value="price_low" <?php echo $sort_by == 'price_low' ? 'selected' : ''; ?>>Price: Low to High</option>
                                        <option value="price_high" <?php echo $sort_by == 'price_high' ? 'selected' : ''; ?>>Price: High to Low</option>
                                    </select>
                                </div>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        </div>

        <!-- Search Results -->
        <div class="card">
            <div class="card-header">
                <div class="flex-between">
                    <h3>
                        <i class="fas fa-list"></i> Search Results
                        <small class="text-secondary">(<?php echo $total_courses; ?> courses found)</small>
                    </h3>
                    <div>
                        <span class="badge badge-success mr-2"><?php echo $free_count; ?> Free</span>
                        <span class="badge badge-primary"><?php echo $paid_count; ?> Paid</span>
                    </div>
                </div>
            </div>
            
            <div class="p-4">
                <?php if (empty($courses)): ?>
                <div class="text-center p-5">
                    <div style="font-size: 4rem; color: #d1d5db;">
                        <i class="fas fa-search"></i>
                    </div>
                    <h3 class="mt-3">No Courses Found</h3>
                    <p class="text-secondary">Try different search terms or filters</p>
                    <a href="student_dashboard.php" class="btn btn-primary mt-3">
                        <i class="fas fa-home"></i> Browse All Courses
                    </a>
                </div>
                <?php else: ?>
                
                <div class="course-grid">
                    <?php foreach ($courses as $course): 
                        $is_enrolled = in_array($course['course_id'], $enrolled_course_ids);
                        $has_video = !empty($course['video_url']) && trim($course['video_url']) !== '';
                        $is_free = $course['price'] == 0;
                    ?>
                    <div class="card course-card">
                        <!-- Price Badge -->
                        <div class="price-badge" style="position: absolute; top: 10px; right: 10px; z-index: 10;">
                            <?php if ($is_free): ?>
                                <span class="badge badge-success">FREE</span>
                            <?php else: ?>
                                <span class="badge badge-primary">$<?php echo number_format($course['price'], 2); ?></span>
                            <?php endif; ?>
                        </div>
                        
                        <!-- Thumbnail -->
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
                        
                        <!-- Course Info -->
                        <div class="course-content">
                            <h4 class="course-title"><?php echo htmlspecialchars($course['title']); ?></h4>
                            <p class="course-description">
                                <?php echo strlen($course['description']) > 100 ? 
                                    substr(htmlspecialchars($course['description']), 0, 100) . '...' : 
                                    htmlspecialchars($course['description']); ?>
                            </p>
                            
                            <div class="course-meta">
                                <div>
                                    <small class="text-secondary">
                                        <i class="fas fa-user-tie"></i> <?php echo htmlspecialchars($course['instructor_name']); ?>
                                    </small><br>
                                    <small class="text-secondary">
                                        <i class="fas fa-layer-group"></i> <?php echo htmlspecialchars($course['category']); ?>
                                        • <i class="fas fa-signal"></i> <?php echo ucfirst($course['difficulty']); ?>
                                        <?php if ($course['rating'] > 0): ?>
                                        • <i class="fas fa-star" style="color: #f59e0b;"></i> <?php echo number_format($course['rating'], 1); ?>
                                        <?php endif; ?>
                                    </small>
                                </div>
                                
                                <!-- Enrollment Button -->
                                <div>
                                    <?php if ($is_enrolled): ?>
                                        <span class="badge badge-success">
                                            <i class="fas fa-check-circle"></i> Enrolled
                                        </span>
                                    <?php elseif (!$has_video): ?>
                                        <button class="btn btn-disabled btn-sm" disabled>
                                            <i class="far fa-clock"></i> Coming Soon
                                        </button>
                                    <?php elseif ($is_free): ?>
                                        <a href="student_dashboard.php?enroll=<?php echo $course['course_id']; ?>"
                                           class="btn btn-primary btn-sm enroll-btn"
                                           onclick="return confirm('Enroll in free course: \"<?php echo addslashes(htmlspecialchars($course['title'])); ?>\"?')">
                                            <i class="fas fa-plus-circle"></i> Enroll Free
                                        </a>
                                    <?php else: ?>
                                        <a href="payment.php?course_id=<?php echo $course['course_id']; ?>"
                                           class="btn btn-success btn-sm enroll-btn">
                                            <i class="fas fa-shopping-cart"></i> Enroll Now
                                        </a>
                                    <?php endif; ?>
                                </div>
                            </div>
                        </div>
                    </div>
                    <?php endforeach; ?>
                </div>
                <?php endif; ?>
            </div>
        </div>
        
        <!-- Search Tips -->
        <div class="card mt-4">
            <div class="card-header">
                <h5><i class="fas fa-lightbulb"></i> Search Tips</h5>
            </div>
            <div class="p-3">
                <div class="row">
                    <div class="col">
                        <ul class="mb-0">
                            <li>Use specific keywords like "Python", "Photoshop", or "Marketing"</li>
                            <li>Filter by category to narrow down results</li>
                            <li>Sort by rating to find the most popular courses</li>
                        </ul>
                    </div>
                    <div class="col">
                        <ul class="mb-0">
                            <li>Free courses are marked with a green "FREE" badge</li>
                            <li>Check difficulty level to match your skill level</li>
                            <li>Enrolled courses show a "Enrolled" badge</li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
    </div>
</body>
</html>