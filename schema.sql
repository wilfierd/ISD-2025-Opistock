-- Drop the database if it exists
DROP DATABASE IF EXISTS inventory_system;

-- Create the database
CREATE DATABASE IF NOT EXISTS inventory_system;
USE inventory_system;

-- Create materials table
CREATE TABLE IF NOT EXISTS materials (
    id INT AUTO_INCREMENT PRIMARY KEY,
    packet_no INT NOT NULL,
    part_name VARCHAR(255) NOT NULL,
    length INT NOT NULL,
    width INT NOT NULL,
    height INT NOT NULL,
    quantity INT NOT NULL,
    supplier VARCHAR(255) NOT NULL,
    updated_by VARCHAR(100) NOT NULL,
    last_updated VARCHAR(10) NOT NULL
);

-- Create users table with phone number field
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    full_name VARCHAR(100) NOT NULL,
    role VARCHAR(20) NOT NULL,
    phone VARCHAR(20),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert default admin user
INSERT INTO users (username, password, full_name, role, phone) VALUES
('admin', 'admin123', 'Administrator', 'admin', '123456789');

-- Insert sample users
INSERT INTO users (username, password, full_name, role, phone) VALUES
('nguyenhieu', 'password123', 'Nguyễn Hieu', 'admin', '123456789'),
('trankhai', 'password123', 'Trần Nguyễn Khải', 'admin', '123456789'),
('lsd_admin', '123456789', 'Nguyen Quoc Hoang An', 'user', '699696969'),
('user1', 'password123', 'Máy móc', 'user', NULL);

-- Insert sample data for materials
INSERT INTO materials (packet_no, part_name, length, width, height, quantity, supplier, updated_by, last_updated) VALUES
(1, 'xxxxxxxxxxxxxxxxxxxxxxxxx', 3000, 3455, 2255, 10, 'SHENZEN', 'Khai', '05/03/2025'),
(1, 'Máy móc', 3000, 345, 10, 10, 'Khai', 'Khai', '05/03/2025'),
(1, 'Máy móc', 3000, 345, 345, 10, 'Khai', 'Khai', '05/03/2025'),
(1, 'Máy móc', 3000, 345, 35, 10, 'Khai', 'Khai', '05/03/2025'),
(1, 'Máy móc', 3000, 345, 345, 10, 'Khai', 'Khai', '05/03/2025'),
(1, 'Máy móc', 3000, 345, 345, 10, 'Khai', 'Khai', '05/03/2025');

CREATE TABLE IF NOT EXISTS employees (
      id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        email VARCHAR(100) UNIQUE,
        phone_number VARCHAR(15) NOT NULL,
        address VARCHAR(255) NOT NULL,
        date_of_birth DATE NOT NULL,
        nation_id INT NULL,
        position VARCHAR(50) NOT NULL,
        salary DECIMAL(10,2) NOT NULL,
        date_hire DATE NOT NULL,
        FOREIGN KEY (nation_id) REFERENCES nations(id) ON DELETE SET NULL ON UPDATE CASCADE);

CREATE TABLE IF NOT EXISTS material_requests (
  id INT PRIMARY KEY AUTO_INCREMENT,
  material_id INT NOT NULL,
  request_type ENUM('update', 'delete') NOT NULL,
  updated_data JSON,
  requested_by INT NOT NULL,
  status ENUM('pending', 'approved', 'rejected') NOT NULL DEFAULT 'pending',
  created_at DATETIME NOT NULL,
  processed_by INT,
  processed_at DATETIME,
  comment TEXT,
  FOREIGN KEY (material_id) REFERENCES materials(id) ON DELETE CASCADE,
  FOREIGN KEY (requested_by) REFERENCES users(id),
  FOREIGN KEY (processed_by) REFERENCES users(id)
);
