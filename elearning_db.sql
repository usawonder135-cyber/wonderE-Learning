-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1
-- Generation Time: Dec 14, 2025 at 04:52 PM
-- Server version: 10.4.32-MariaDB
-- PHP Version: 8.2.12

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `elearning_db`
--

-- --------------------------------------------------------

--
-- Table structure for table `categories`
--

CREATE TABLE `categories` (
  `id` int(11) NOT NULL,
  `name` varchar(100) NOT NULL,
  `description` text DEFAULT NULL,
  `created_at` datetime DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `courses`
--

CREATE TABLE `courses` (
  `id` int(11) NOT NULL,
  `title` varchar(200) NOT NULL,
  `description` text DEFAULT NULL,
  `thumbnail_image` varchar(255) DEFAULT NULL,
  `video_url` varchar(255) DEFAULT NULL,
  `created_by` int(11) NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `has_quiz` tinyint(1) DEFAULT 0,
  `price` decimal(10,2) DEFAULT 0.00,
  `category_id` int(11) DEFAULT 1,
  `difficulty` enum('beginner','intermediate','advanced') DEFAULT 'beginner',
  `rating` decimal(3,2) DEFAULT 0.00,
  `category` varchar(100) DEFAULT 'General'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `courses`
--

INSERT INTO `courses` (`id`, `title`, `description`, `thumbnail_image`, `video_url`, `created_by`, `created_at`, `has_quiz`, `price`, `category_id`, `difficulty`, `rating`, `category`) VALUES
(2, 'Data science', 'get information about data science', 'uploads/thumbnail_1765661174_693dd9f65911d.jpg', 'https://www.youtube.com/embed/qz0aGYrrlhU', 1, '2025-12-13 21:26:14', 1, 99.99, 1, 'advanced', 3.90, 'Business'),
(3, 'datascience', 'learn data science in 3 minutes', 'uploads/thumbnail_1765661825_693ddc8160844.jpg', 'https://youtu.be/LTqy-CH50zs?si=PSW41TlhivMY4GVa', 1, '2025-12-13 21:37:05', 0, 0.00, 1, 'beginner', 4.40, 'Technology'),
(5, 'Introduction to Python', 'Learn Python programming basics with hands-on examples', 'assets/python-course.jpg', 'https://www.youtube.com/embed/_uQrJ0TkZlc', 1, '2025-12-14 13:00:22', 0, 0.00, 1, 'beginner', 0.00, 'Programming'),
(6, 'Web Design Fundamentals', 'Master HTML, CSS, and responsive design', 'assets/web-design.jpg', 'https://www.youtube.com/embed/qz0aGYrrlhU', 1, '2025-12-14 13:00:22', 0, 49.99, 1, 'beginner', 0.00, 'Design'),
(7, 'Data Science Essentials', 'Learn data analysis, visualization, and machine learning', 'assets/data-science.jpg', 'https://www.youtube.com/embed/ua-CiDNNj30', 1, '2025-12-14 13:00:22', 0, 0.00, 1, 'intermediate', 0.00, 'Programming'),
(8, 'Digital Marketing Mastery', 'Social media, SEO, and content marketing strategies', 'assets/digital-marketing.jpg', 'https://www.youtube.com/embed/QcWpYYpGqmo', 1, '2025-12-14 13:00:22', 0, 79.99, 1, 'beginner', 0.00, 'Business'),
(9, 'Graphic Design for Beginners', 'Learn Photoshop and Illustrator basics', 'assets/graphic-design.jpg', 'https://www.youtube.com/embed/WONZVnlam6U', 1, '2025-12-14 13:00:22', 0, 0.00, 1, 'beginner', 0.00, 'Design'),
(10, 'Python Programming', 'Learn Python basics for beginners', NULL, 'https://www.youtube.com/embed/QcWpYYpGqmo', 1, '2025-12-14 13:10:07', 0, 0.00, 1, 'beginner', 0.00, 'Programming'),
(11, 'Web Design Pro', 'Professional web design course', NULL, 'https://www.youtube.com/embed/WONZVnlam6U', 1, '2025-12-14 13:10:07', 0, 49.99, 1, 'beginner', 0.00, 'Design');

-- --------------------------------------------------------

--
-- Table structure for table `enrollments`
--

CREATE TABLE `enrollments` (
  `id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `course_id` int(11) NOT NULL,
  `enrollment_date` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `enrollments`
--

INSERT INTO `enrollments` (`id`, `user_id`, `course_id`, `enrollment_date`) VALUES
(1, 2, 2, '2025-12-13 21:33:24'),
(3, 2, 3, '2025-12-13 21:38:08'),
(4, 2, 5, '2025-12-14 13:03:54'),
(5, 2, 11, '2025-12-14 13:51:16');

-- --------------------------------------------------------

--
-- Table structure for table `quizzes`
--

CREATE TABLE `quizzes` (
  `id` int(11) NOT NULL,
  `course_id` int(11) NOT NULL,
  `title` varchar(200) NOT NULL,
  `description` text DEFAULT NULL,
  `total_questions` int(11) DEFAULT 0,
  `passing_score` int(11) DEFAULT 70,
  `time_limit` int(11) DEFAULT 30,
  `is_active` tinyint(1) DEFAULT 1,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `quizzes`
--

INSERT INTO `quizzes` (`id`, `course_id`, `title`, `description`, `total_questions`, `passing_score`, `time_limit`, `is_active`, `created_at`, `updated_at`) VALUES
(1, 2, 'gdfjhm', 'gdfklhk', 0, 70, 30, 0, '2025-12-14 08:04:26', '2025-12-14 09:45:10'),
(2, 2, 'take quiz', 'you have to take it', 0, 70, 30, 0, '2025-12-14 08:11:57', '2025-12-14 12:05:45'),
(3, 2, 'take quiz', 'you have to take it', 1, 70, 30, 1, '2025-12-14 08:11:57', '2025-12-14 08:14:01'),
(7, 5, 'Python Basics Assessment', 'Test your understanding of Python programming fundamentals', 0, 70, 10, 1, '2025-12-14 13:25:06', '2025-12-14 13:25:06');

-- --------------------------------------------------------

--
-- Table structure for table `quiz_answers`
--

CREATE TABLE `quiz_answers` (
  `id` int(11) NOT NULL,
  `attempt_id` int(11) NOT NULL,
  `question_id` int(11) NOT NULL,
  `selected_option_id` int(11) DEFAULT NULL,
  `is_correct` tinyint(1) DEFAULT 0,
  `points_earned` int(11) DEFAULT 0,
  `answered_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `quiz_attempts`
--

CREATE TABLE `quiz_attempts` (
  `id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `quiz_id` int(11) NOT NULL,
  `score` int(11) DEFAULT 0,
  `total_questions` int(11) DEFAULT 0,
  `correct_answers` int(11) DEFAULT 0,
  `time_taken` int(11) DEFAULT 0,
  `status` enum('in_progress','completed','failed') DEFAULT 'in_progress',
  `started_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `completed_at` timestamp NULL DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `quiz_attempts`
--

INSERT INTO `quiz_attempts` (`id`, `user_id`, `quiz_id`, `score`, `total_questions`, `correct_answers`, `time_taken`, `status`, `started_at`, `completed_at`) VALUES
(1, 2, 2, 0, 0, 0, 0, 'in_progress', '2025-12-14 10:59:15', NULL),
(2, 2, 2, 0, 0, 0, 0, 'in_progress', '2025-12-14 10:59:31', NULL),
(3, 2, 2, 0, 0, 0, 0, 'in_progress', '2025-12-14 10:59:31', NULL),
(4, 2, 2, 0, 0, 0, 0, 'in_progress', '2025-12-14 11:15:44', NULL),
(5, 2, 2, 0, 0, 0, 0, 'in_progress', '2025-12-14 11:15:54', NULL),
(6, 2, 2, 0, 0, 0, 0, 'in_progress', '2025-12-14 11:15:54', NULL),
(7, 2, 3, 0, 0, 0, 0, 'in_progress', '2025-12-14 11:34:19', NULL),
(8, 2, 2, 0, 0, 0, 0, 'in_progress', '2025-12-14 11:34:38', NULL),
(9, 2, 3, 0, 0, 0, 0, 'in_progress', '2025-12-14 11:42:09', NULL),
(10, 2, 2, 0, 0, 0, 0, 'in_progress', '2025-12-14 11:42:19', NULL),
(11, 2, 2, 0, 0, 0, 0, 'in_progress', '2025-12-14 11:45:15', NULL),
(12, 2, 3, 0, 0, 0, 0, 'in_progress', '2025-12-14 11:45:27', NULL),
(13, 2, 3, 0, 0, 0, 0, 'in_progress', '2025-12-14 11:56:39', NULL),
(14, 2, 2, 0, 0, 0, 0, 'in_progress', '2025-12-14 11:56:45', NULL),
(15, 2, 2, 0, 0, 0, 0, 'in_progress', '2025-12-14 11:56:51', NULL),
(16, 2, 3, 0, 0, 0, 0, 'in_progress', '2025-12-14 11:57:33', NULL),
(17, 2, 2, 0, 0, 0, 0, 'in_progress', '2025-12-14 11:58:31', NULL),
(18, 2, 3, 0, 0, 0, 0, 'in_progress', '2025-12-14 12:06:05', NULL),
(19, 2, 3, 0, 0, 0, 0, 'in_progress', '2025-12-14 12:06:18', NULL),
(20, 2, 3, 0, 0, 0, 0, 'in_progress', '2025-12-14 12:06:33', NULL),
(21, 2, 3, 0, 0, 0, 0, 'in_progress', '2025-12-14 12:09:24', NULL),
(22, 2, 3, 0, 0, 0, 0, 'in_progress', '2025-12-14 12:10:15', NULL),
(23, 2, 3, 0, 0, 0, 0, 'in_progress', '2025-12-14 12:12:23', NULL),
(24, 2, 3, 0, 0, 0, 0, 'in_progress', '2025-12-14 12:12:32', NULL),
(25, 2, 3, 0, 0, 0, 0, 'in_progress', '2025-12-14 12:12:44', NULL),
(26, 2, 3, 0, 0, 0, 0, 'in_progress', '2025-12-14 12:22:32', NULL),
(27, 2, 3, 0, 0, 0, 0, 'in_progress', '2025-12-14 12:22:40', NULL),
(28, 2, 3, 0, 0, 0, 0, 'in_progress', '2025-12-14 12:42:37', NULL),
(29, 2, 3, 0, 0, 0, 0, 'in_progress', '2025-12-14 12:53:54', NULL),
(30, 2, 3, 0, 0, 0, 0, 'in_progress', '2025-12-14 13:08:14', NULL),
(31, 2, 7, 0, 0, 0, 0, 'in_progress', '2025-12-14 13:44:26', NULL),
(32, 2, 7, 0, 0, 0, 0, 'in_progress', '2025-12-14 13:45:12', NULL),
(33, 2, 7, 0, 0, 0, 0, 'in_progress', '2025-12-14 13:45:12', NULL),
(34, 2, 7, 0, 0, 0, 0, 'in_progress', '2025-12-14 13:45:42', NULL),
(35, 2, 7, 0, 0, 0, 0, 'in_progress', '2025-12-14 13:45:43', NULL),
(36, 2, 7, 0, 0, 0, 0, 'in_progress', '2025-12-14 14:00:04', NULL),
(37, 2, 7, 0, 0, 0, 0, 'in_progress', '2025-12-14 14:03:03', NULL),
(38, 2, 7, 0, 0, 0, 0, 'in_progress', '2025-12-14 14:03:03', NULL),
(39, 2, 7, 0, 0, 0, 0, 'in_progress', '2025-12-14 14:11:46', NULL),
(40, 2, 7, 0, 0, 0, 0, 'in_progress', '2025-12-14 14:11:46', NULL),
(41, 2, 7, 0, 0, 0, 0, 'in_progress', '2025-12-14 14:12:59', NULL),
(42, 2, 7, 0, 0, 0, 0, 'in_progress', '2025-12-14 14:13:36', NULL),
(43, 2, 7, 0, 0, 0, 0, 'in_progress', '2025-12-14 15:12:32', NULL),
(44, 2, 7, 0, 0, 0, 0, 'in_progress', '2025-12-14 15:12:50', NULL),
(45, 2, 7, 0, 0, 0, 0, 'in_progress', '2025-12-14 15:13:08', NULL),
(46, 2, 7, 0, 0, 0, 0, 'in_progress', '2025-12-14 15:24:56', NULL),
(47, 2, 7, 0, 0, 0, 0, 'in_progress', '2025-12-14 15:31:08', NULL),
(48, 2, 7, 0, 0, 0, 0, 'in_progress', '2025-12-14 15:31:25', NULL),
(49, 2, 7, 0, 0, 0, 0, 'in_progress', '2025-12-14 15:32:05', NULL),
(50, 2, 7, 0, 0, 0, 0, 'in_progress', '2025-12-14 15:32:19', NULL),
(51, 2, 7, 0, 0, 0, 0, 'in_progress', '2025-12-14 15:45:55', NULL),
(52, 2, 7, 0, 0, 0, 0, 'in_progress', '2025-12-14 15:46:09', NULL),
(53, 2, 3, 0, 0, 0, 0, 'in_progress', '2025-12-14 15:46:19', NULL),
(54, 2, 3, 0, 0, 0, 0, 'in_progress', '2025-12-14 15:46:24', NULL),
(55, 2, 3, 0, 0, 0, 0, 'in_progress', '2025-12-14 15:46:28', NULL),
(56, 2, 3, 0, 0, 0, 0, 'in_progress', '2025-12-14 15:46:35', NULL);

-- --------------------------------------------------------

--
-- Table structure for table `quiz_options`
--

CREATE TABLE `quiz_options` (
  `id` int(11) NOT NULL,
  `question_id` int(11) NOT NULL,
  `option_text` varchar(255) NOT NULL,
  `is_correct` tinyint(1) DEFAULT 0,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `quiz_options`
--

INSERT INTO `quiz_options` (`id`, `question_id`, `option_text`, `is_correct`, `created_at`) VALUES
(1, 1, 'information', 1, '2025-12-14 08:14:00'),
(2, 1, 'collection of characters numbers and etc', 0, '2025-12-14 08:14:00'),
(3, 1, 'processed information', 0, '2025-12-14 08:14:00'),
(4, 1, 'none', 0, '2025-12-14 08:14:01'),
(5, 2, 'Web Development', 0, '2025-12-14 13:25:07'),
(6, 2, 'Data Analysis', 0, '2025-12-14 13:25:07'),
(7, 2, 'Artificial Intelligence', 0, '2025-12-14 13:25:07'),
(8, 2, 'All of the above', 1, '2025-12-14 13:25:07'),
(9, 3, '//', 0, '2025-12-14 13:25:07'),
(10, 3, '#', 1, '2025-12-14 13:25:07'),
(11, 3, '/*', 0, '2025-12-14 13:25:07'),
(12, 3, '--', 0, '2025-12-14 13:25:07'),
(13, 4, '6', 0, '2025-12-14 13:25:07'),
(14, 4, '8', 1, '2025-12-14 13:25:08'),
(15, 4, '9', 0, '2025-12-14 13:25:08'),
(16, 4, '23', 0, '2025-12-14 13:25:08'),
(17, 5, 'True', 1, '2025-12-14 13:25:08'),
(18, 5, 'False', 0, '2025-12-14 13:25:08'),
(19, 6, 'True', 1, '2025-12-14 13:25:09'),
(20, 6, 'False', 0, '2025-12-14 13:25:09');

-- --------------------------------------------------------

--
-- Table structure for table `quiz_questions`
--

CREATE TABLE `quiz_questions` (
  `id` int(11) NOT NULL,
  `quiz_id` int(11) NOT NULL,
  `question_text` text NOT NULL,
  `question_type` enum('multiple_choice','true_false') DEFAULT 'multiple_choice',
  `points` int(11) DEFAULT 1,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `quiz_questions`
--

INSERT INTO `quiz_questions` (`id`, `quiz_id`, `question_text`, `question_type`, `points`, `created_at`) VALUES
(1, 3, 'What is Data?', 'multiple_choice', 1, '2025-12-14 08:14:00'),
(2, 7, 'What is Python primarily used for?', 'multiple_choice', 1, '2025-12-14 13:25:06'),
(3, 7, 'Which symbol is used for single-line comments in Python?', 'multiple_choice', 1, '2025-12-14 13:25:07'),
(4, 7, 'What is the output of: print(2 ** 3) in Python?', 'multiple_choice', 1, '2025-12-14 13:25:07'),
(5, 7, 'Python is an interpreted language.', 'true_false', 1, '2025-12-14 13:25:08'),
(6, 7, 'Lists in Python are mutable (can be changed).', 'true_false', 1, '2025-12-14 13:25:08');

-- --------------------------------------------------------

--
-- Table structure for table `transactions`
--

CREATE TABLE `transactions` (
  `id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `course_id` int(11) NOT NULL,
  `amount` decimal(10,2) NOT NULL,
  `payment_method` varchar(50) NOT NULL,
  `transaction_id` varchar(100) NOT NULL,
  `status` enum('pending','completed','failed','refunded') DEFAULT 'pending',
  `created_at` datetime DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `transactions`
--

INSERT INTO `transactions` (`id`, `user_id`, `course_id`, `amount`, `payment_method`, `transaction_id`, `status`, `created_at`) VALUES
(1, 2, 11, 49.99, 'cbe', 'TXN-1765720276-5317', 'completed', '2025-12-14 16:51:16');

-- --------------------------------------------------------

--
-- Table structure for table `users`
--

CREATE TABLE `users` (
  `id` int(11) NOT NULL,
  `full_name` varchar(100) NOT NULL,
  `email` varchar(100) NOT NULL,
  `password` varchar(255) NOT NULL,
  `role` enum('admin','student') NOT NULL DEFAULT 'student',
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `users`
--

INSERT INTO `users` (`id`, `full_name`, `email`, `password`, `role`, `created_at`) VALUES
(1, 'Admin User', 'admin@test.com', '$2y$10$OVSNqLxG1pOGVBkOox8loetTNElRyJkbrBqb.nOBWMbUUh8mbU0K.', 'admin', '2025-12-13 19:52:44'),
(2, 'Student User', 'student@test.com', '$2y$10$6kFcRYmAKUPa1FZ97bpAAOlTWbfjrTY3splkQMSk/8FnX2P9CSNUi', 'student', '2025-12-13 19:52:44');

-- --------------------------------------------------------

--
-- Table structure for table `user_quiz_progress`
--

CREATE TABLE `user_quiz_progress` (
  `user_id` int(11) NOT NULL,
  `course_id` int(11) NOT NULL,
  `quiz_id` int(11) NOT NULL,
  `best_score` decimal(5,2) DEFAULT 0.00,
  `attempts_count` int(11) DEFAULT 0,
  `passed` tinyint(1) DEFAULT 0,
  `last_attempt` datetime DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Indexes for dumped tables
--

--
-- Indexes for table `categories`
--
ALTER TABLE `categories`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `courses`
--
ALTER TABLE `courses`
  ADD PRIMARY KEY (`id`),
  ADD KEY `created_by` (`created_by`);

--
-- Indexes for table `enrollments`
--
ALTER TABLE `enrollments`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `unique_enrollment` (`user_id`,`course_id`),
  ADD KEY `course_id` (`course_id`);

--
-- Indexes for table `quizzes`
--
ALTER TABLE `quizzes`
  ADD PRIMARY KEY (`id`),
  ADD KEY `course_id` (`course_id`);

--
-- Indexes for table `quiz_answers`
--
ALTER TABLE `quiz_answers`
  ADD PRIMARY KEY (`id`),
  ADD KEY `attempt_id` (`attempt_id`),
  ADD KEY `question_id` (`question_id`),
  ADD KEY `selected_option_id` (`selected_option_id`);

--
-- Indexes for table `quiz_attempts`
--
ALTER TABLE `quiz_attempts`
  ADD PRIMARY KEY (`id`),
  ADD KEY `user_id` (`user_id`),
  ADD KEY `quiz_id` (`quiz_id`);

--
-- Indexes for table `quiz_options`
--
ALTER TABLE `quiz_options`
  ADD PRIMARY KEY (`id`),
  ADD KEY `question_id` (`question_id`);

--
-- Indexes for table `quiz_questions`
--
ALTER TABLE `quiz_questions`
  ADD PRIMARY KEY (`id`),
  ADD KEY `quiz_id` (`quiz_id`);

--
-- Indexes for table `transactions`
--
ALTER TABLE `transactions`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `transaction_id` (`transaction_id`),
  ADD KEY `user_id` (`user_id`),
  ADD KEY `course_id` (`course_id`);

--
-- Indexes for table `users`
--
ALTER TABLE `users`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `email` (`email`);

--
-- Indexes for table `user_quiz_progress`
--
ALTER TABLE `user_quiz_progress`
  ADD PRIMARY KEY (`user_id`,`quiz_id`),
  ADD KEY `course_id` (`course_id`),
  ADD KEY `quiz_id` (`quiz_id`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `categories`
--
ALTER TABLE `categories`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `courses`
--
ALTER TABLE `courses`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=12;

--
-- AUTO_INCREMENT for table `enrollments`
--
ALTER TABLE `enrollments`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=6;

--
-- AUTO_INCREMENT for table `quizzes`
--
ALTER TABLE `quizzes`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=8;

--
-- AUTO_INCREMENT for table `quiz_answers`
--
ALTER TABLE `quiz_answers`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `quiz_attempts`
--
ALTER TABLE `quiz_attempts`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=57;

--
-- AUTO_INCREMENT for table `quiz_options`
--
ALTER TABLE `quiz_options`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=21;

--
-- AUTO_INCREMENT for table `quiz_questions`
--
ALTER TABLE `quiz_questions`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=7;

--
-- AUTO_INCREMENT for table `transactions`
--
ALTER TABLE `transactions`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- AUTO_INCREMENT for table `users`
--
ALTER TABLE `users`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=3;

--
-- Constraints for dumped tables
--

--
-- Constraints for table `courses`
--
ALTER TABLE `courses`
  ADD CONSTRAINT `courses_ibfk_1` FOREIGN KEY (`created_by`) REFERENCES `users` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `enrollments`
--
ALTER TABLE `enrollments`
  ADD CONSTRAINT `enrollments_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `enrollments_ibfk_2` FOREIGN KEY (`course_id`) REFERENCES `courses` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `quizzes`
--
ALTER TABLE `quizzes`
  ADD CONSTRAINT `quizzes_ibfk_1` FOREIGN KEY (`course_id`) REFERENCES `courses` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `quiz_answers`
--
ALTER TABLE `quiz_answers`
  ADD CONSTRAINT `quiz_answers_ibfk_1` FOREIGN KEY (`attempt_id`) REFERENCES `quiz_attempts` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `quiz_answers_ibfk_2` FOREIGN KEY (`question_id`) REFERENCES `quiz_questions` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `quiz_answers_ibfk_3` FOREIGN KEY (`selected_option_id`) REFERENCES `quiz_options` (`id`) ON DELETE SET NULL;

--
-- Constraints for table `quiz_attempts`
--
ALTER TABLE `quiz_attempts`
  ADD CONSTRAINT `quiz_attempts_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `quiz_attempts_ibfk_2` FOREIGN KEY (`quiz_id`) REFERENCES `quizzes` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `quiz_options`
--
ALTER TABLE `quiz_options`
  ADD CONSTRAINT `quiz_options_ibfk_1` FOREIGN KEY (`question_id`) REFERENCES `quiz_questions` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `quiz_questions`
--
ALTER TABLE `quiz_questions`
  ADD CONSTRAINT `quiz_questions_ibfk_1` FOREIGN KEY (`quiz_id`) REFERENCES `quizzes` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `transactions`
--
ALTER TABLE `transactions`
  ADD CONSTRAINT `transactions_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`),
  ADD CONSTRAINT `transactions_ibfk_2` FOREIGN KEY (`course_id`) REFERENCES `courses` (`id`);

--
-- Constraints for table `user_quiz_progress`
--
ALTER TABLE `user_quiz_progress`
  ADD CONSTRAINT `user_quiz_progress_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`),
  ADD CONSTRAINT `user_quiz_progress_ibfk_2` FOREIGN KEY (`course_id`) REFERENCES `courses` (`id`),
  ADD CONSTRAINT `user_quiz_progress_ibfk_3` FOREIGN KEY (`quiz_id`) REFERENCES `quizzes` (`id`);
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
