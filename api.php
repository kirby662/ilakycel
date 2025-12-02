<?php
// api.php - Complete Backend for E-commerce System

// Enable error reporting for development
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Start session at the beginning
session_start();

// Database configuration
define('DB_HOST', 'localhost');
define('DB_NAME', 'kycel');
define('DB_USER', 'root');
define('DB_PASS', '');

// Set headers for JSON response
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, GET, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

// Handle preflight requests
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    exit(0);
}

// Database connection class
class Database {
    private $conn;
    
    public function __construct() {
        try {
            $this->conn = new PDO(
                "mysql:host=" . DB_HOST . ";dbname=" . DB_NAME,
                DB_USER,
                DB_PASS,
                [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]
            );
        } catch(PDOException $e) {
            echo json_encode([
                'success' => false,
                'message' => "Database connection failed: " . $e->getMessage()
            ]);
            exit;
        }
    }
    
    public function getConnection() {
        return $this->conn;
    }
}

// User authentication class
class UserAuth {
    private $db;
    
    public function __construct($database) {
        $this->db = $database->getConnection();
        $this->createUsersTable();
        $this->createLoginHistoryTable();
    }
    
    private function createUsersTable() {
        $sql = "CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(100) NOT NULL,
            email VARCHAR(100),
            phone VARCHAR(20),
            password VARCHAR(255) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            UNIQUE KEY unique_username (username),
            UNIQUE KEY unique_email (email)
        )";
        
        try {
            $this->db->exec($sql);
        } catch(PDOException $e) {
            error_log("Users table creation error: " . $e->getMessage());
        }
    }
    
    private function createLoginHistoryTable() {
        $sql = "CREATE TABLE IF NOT EXISTS login_history (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT,
            username VARCHAR(100),
            login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            ip_address VARCHAR(45),
            user_agent TEXT,
            success BOOLEAN DEFAULT TRUE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )";
        
        try {
            $this->db->exec($sql);
        } catch(PDOException $e) {
            error_log("Login history table creation error: " . $e->getMessage());
        }
    }
    
    private function logLoginAttempt($userId, $username, $success = true) {
        $sql = "INSERT INTO login_history (user_id, username, ip_address, user_agent, success) 
                VALUES (:user_id, :username, :ip_address, :user_agent, :success)";
        
        try {
            $stmt = $this->db->prepare($sql);
            $stmt->execute([
                ':user_id' => $userId,
                ':username' => $username,
                ':ip_address' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
                ':user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
                ':success' => $success ? 1 : 0
            ]);
        } catch(PDOException $e) {
            error_log("Login history error: " . $e->getMessage());
        }
    }
    
    public function register($data) {
        // Validate input
        if (empty($data['username']) || empty($data['password'])) {
            return ['success' => false, 'message' => 'Username and password are required'];
        }
        
        // Check if user already exists
        $checkSql = "SELECT id FROM users WHERE username = :username";
        $checkStmt = $this->db->prepare($checkSql);
        $checkStmt->execute([':username' => $data['username']]);
        
        if ($checkStmt->fetch()) {
            return ['success' => false, 'message' => 'Username already exists'];
        }
        
        // Check if email already exists (if provided)
        if (!empty($data['email'])) {
            $checkEmailSql = "SELECT id FROM users WHERE email = :email";
            $checkEmailStmt = $this->db->prepare($checkEmailSql);
            $checkEmailStmt->execute([':email' => $data['email']]);
            
            if ($checkEmailStmt->fetch()) {
                return ['success' => false, 'message' => 'Email already exists'];
            }
        }
        
        // Hash password
        $passwordHash = password_hash($data['password'], PASSWORD_BCRYPT);
        
        // Prepare SQL
        $sql = "INSERT INTO users (username, email, phone, password) 
                VALUES (:username, :email, :phone, :password)";
        
        try {
            $stmt = $this->db->prepare($sql);
            $stmt->execute([
                ':username' => $data['username'],
                ':email' => !empty($data['email']) ? $data['email'] : null,
                ':phone' => !empty($data['phone']) ? $data['phone'] : null,
                ':password' => $passwordHash
            ]);
            
            $userId = $this->db->lastInsertId();
            
            // Log successful registration as a login
            $this->logLoginAttempt($userId, $data['username'], true);
            
            // Set session
            $_SESSION['user_id'] = $userId;
            $_SESSION['username'] = $data['username'];
            
            return [
                'success' => true,
                'message' => 'Registration successful',
                'user_id' => $userId,
                'username' => $data['username']
            ];
        } catch(PDOException $e) {
            return [
                'success' => false,
                'message' => 'Registration failed: ' . $e->getMessage()
            ];
        }
    }
    
    public function login($data) {
        if (empty($data['username']) || empty($data['password'])) {
            return ['success' => false, 'message' => 'Username and password are required'];
        }
        
        $sql = "SELECT * FROM users WHERE username = :username OR email = :username OR phone = :username LIMIT 1";
        
        try {
            $stmt = $this->db->prepare($sql);
            $stmt->execute([':username' => $data['username']]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if ($user && password_verify($data['password'], $user['password'])) {
                // Log successful login
                $this->logLoginAttempt($user['id'], $user['username'], true);
                
                // Set session variables
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['username'] = $user['username'];
                $_SESSION['email'] = $user['email'];
                $_SESSION['login_time'] = time();
                
                return [
                    'success' => true,
                    'message' => 'Login successful',
                    'user' => [
                        'id' => $user['id'],
                        'username' => $user['username'],
                        'email' => $user['email'],
                        'phone' => $user['phone']
                    ]
                ];
            } else {
                // Log failed login attempt
                if ($user) {
                    $this->logLoginAttempt($user['id'], $data['username'], false);
                } else {
                    $this->logLoginAttempt(null, $data['username'], false);
                }
                
                return ['success' => false, 'message' => 'Invalid username or password'];
            }
        } catch(PDOException $e) {
            return ['success' => false, 'message' => 'Login error: ' . $e->getMessage()];
        }
    }
    
    public function logout() {
        session_unset();
        session_destroy();
        return ['success' => true, 'message' => 'Logged out successfully'];
    }
    
    public function checkSession() {
        if (isset($_SESSION['user_id'])) {
            return [
                'success' => true,
                'logged_in' => true,
                'user' => [
                    'id' => $_SESSION['user_id'],
                    'username' => $_SESSION['username'],
                    'email' => $_SESSION['email'] ?? null
                ]
            ];
        } else {
            return [
                'success' => true,
                'logged_in' => false
            ];
        }
    }
}

// Order management class
class OrderManager {
    private $db;
    
    public function __construct($database) {
        $this->db = $database->getConnection();
        $this->createOrdersTable();
    }
    
    private function createOrdersTable() {
        // First check if users table exists
        $checkUserTable = "SHOW TABLES LIKE 'users'";
        $result = $this->db->query($checkUserTable);
        
        if ($result->rowCount() == 0) {
            error_log("Users table doesn't exist yet, skipping orders table creation");
            return;
        }
        
        $sql = "CREATE TABLE IF NOT EXISTS orders (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT,
            product_name VARCHAR(255) NOT NULL,
            delivery_address TEXT NOT NULL,
            quantity INT NOT NULL,
            total_price DECIMAL(10,2),
            status VARCHAR(50) DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_user_id (user_id)
        )";
        
        try {
            $this->db->exec($sql);
            
            // Add foreign key constraint separately to handle errors better
            try {
                $fkSql = "ALTER TABLE orders ADD CONSTRAINT fk_orders_user 
                          FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL";
                $this->db->exec($fkSql);
            } catch(PDOException $e) {
                // Foreign key might already exist, that's okay
                if (strpos($e->getMessage(), 'Duplicate') === false) {
                    error_log("Foreign key creation: " . $e->getMessage());
                }
            }
        } catch(PDOException $e) {
            error_log("Orders table creation error: " . $e->getMessage());
        }
    }
    
    public function createOrder($data) {
        if (empty($data['product']) || empty($data['address']) || empty($data['quantity'])) {
            return ['success' => false, 'message' => 'Missing order information'];
        }
        
        // Get user ID from session if logged in
        $userId = isset($_SESSION['user_id']) ? $_SESSION['user_id'] : null;
        
        // Calculate price (simplified)
        $basePrice = 2500.00;
        $totalPrice = $basePrice * intval($data['quantity']);
        
        $sql = "INSERT INTO orders (user_id, product_name, delivery_address, quantity, total_price, status) 
                VALUES (:user_id, :product_name, :delivery_address, :quantity, :total_price, 'pending')";
        
        try {
            $stmt = $this->db->prepare($sql);
            $stmt->execute([
                ':user_id' => $userId,
                ':product_name' => $data['product'],
                ':delivery_address' => $data['address'],
                ':quantity' => $data['quantity'],
                ':total_price' => $totalPrice
            ]);
            
            return [
                'success' => true,
                'message' => 'Order placed successfully',
                'order_id' => $this->db->lastInsertId(),
                'total_price' => $totalPrice
            ];
        } catch(PDOException $e) {
            return ['success' => false, 'message' => 'Order creation failed: ' . $e->getMessage()];
        }
    }
    
    public function getOrders($userId = null) {
        if ($userId) {
            $sql = "SELECT * FROM orders WHERE user_id = :user_id ORDER BY created_at DESC";
            $stmt = $this->db->prepare($sql);
            $stmt->execute([':user_id' => $userId]);
        } else {
            $sql = "SELECT * FROM orders ORDER BY created_at DESC";
            $stmt = $this->db->prepare($sql);
            $stmt->execute();
        }
        
        $orders = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        return [
            'success' => true,
            'orders' => $orders
        ];
    }
}

// Product management class
class ProductManager {
    private $db;
    
    public function __construct($database) {
        $this->db = $database->getConnection();
        $this->createProductsTable();
        $this->seedProducts();
    }
    
    private function createProductsTable() {
        $sql = "CREATE TABLE IF NOT EXISTS products (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            description TEXT,
            price DECIMAL(10,2) NOT NULL,
            category VARCHAR(100),
            stock INT DEFAULT 0,
            image_url VARCHAR(255),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )";
        
        try {
            $this->db->exec($sql);
        } catch(PDOException $e) {
            error_log("Products table creation error: " . $e->getMessage());
        }
    }
    
    private function seedProducts() {
        $checkSql = "SELECT COUNT(*) FROM products";
        $stmt = $this->db->query($checkSql);
        $count = $stmt->fetchColumn();
        
        if ($count > 0) {
            return;
        }
        
        $products = [
            ['Razer Gaming Mouse', 'Wireless gaming mouse with RGB lighting', 2500.00, 'Mouse', 50],
            ['Mechanical Keyboard', 'RGB backlit mechanical keyboard', 3500.00, 'Keyboard', 30],
            ['Gaming Monitor', '144Hz refresh rate, 1ms response time', 15000.00, 'Monitor', 20],
            ['Gaming Headset', '7.1 surround sound with noise cancellation', 2800.00, 'Headphone', 40]
        ];
        
        $sql = "INSERT INTO products (name, description, price, category, stock) VALUES (?, ?, ?, ?, ?)";
        
        try {
            $stmt = $this->db->prepare($sql);
            foreach ($products as $product) {
                $stmt->execute($product);
            }
        } catch(PDOException $e) {
            error_log("Product seeding error: " . $e->getMessage());
        }
    }
    
    public function getProducts($category = null) {
        if ($category) {
            $sql = "SELECT * FROM products WHERE category = :category AND stock > 0";
            $stmt = $this->db->prepare($sql);
            $stmt->execute([':category' => $category]);
        } else {
            $sql = "SELECT * FROM products WHERE stock > 0";
            $stmt = $this->db->prepare($sql);
            $stmt->execute();
        }
        
        $products = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        return [
            'success' => true,
            'products' => $products
        ];
    }
}

// Main API handler
function handleRequest() {
    $database = new Database();
    
    // Get request data
    $input = file_get_contents('php://input');
    $data = json_decode($input, true);
    
    if (!$data || !isset($data['action'])) {
        echo json_encode(['success' => false, 'message' => 'Invalid request - no action specified']);
        return;
    }
    
    $action = $data['action'];
    $requestData = isset($data['data']) ? $data['data'] : [];
    
    switch ($action) {
        case 'register':
            $auth = new UserAuth($database);
            $result = $auth->register($requestData);
            echo json_encode($result);
            break;
            
        case 'login':
            $auth = new UserAuth($database);
            $result = $auth->login($requestData);
            echo json_encode($result);
            break;
            
        case 'logout':
            $auth = new UserAuth($database);
            $result = $auth->logout();
            echo json_encode($result);
            break;
            
        case 'check_session':
            $auth = new UserAuth($database);
            $result = $auth->checkSession();
            echo json_encode($result);
            break;
            
        case 'checkout':
            $orders = new OrderManager($database);
            $result = $orders->createOrder($requestData);
            echo json_encode($result);
            break;
            
        case 'get_orders':
            $orders = new OrderManager($database);
            $userId = isset($_SESSION['user_id']) ? $_SESSION['user_id'] : null;
            $result = $orders->getOrders($userId);
            echo json_encode($result);
            break;
            
        case 'get_products':
            $products = new ProductManager($database);
            $category = isset($requestData['category']) ? $requestData['category'] : null;
            $result = $products->getProducts($category);
            echo json_encode($result);
            break;
            
        default:
            echo json_encode(['success' => false, 'message' => 'Unknown action: ' . $action]);
            break;
    }
}

// Run the API handler
handleRequest();
?>