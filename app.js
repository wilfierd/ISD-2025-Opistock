// app.js - Main Express application
const cors = require('cors');
const express = require('express');
const path = require('path');
const mysql = require('mysql2/promise');
const bodyParser = require('body-parser');
const session = require('express-session');
const app = express();
require('dotenv').config();
const PORT = process.env.PORT || 3000;

// Database connection pool
const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT || 3306,
    waitForConnections: true,
    connectionLimit: process.env.DB_CONNECTION_LIMIT || 10,
    queueLimit: 0
});

// Middlewares
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: process.env.SESSION_SECRET || 'inventory-management-secret-key',
  resave: false,
  saveUninitialized: true,
  cookie: { maxAge: 24 * 60 * 60 * 1000 } 
}));

// CORS configuration
app.use(cors({
  origin: ['http://localhost:3001', 'http://localhost:3000'],
  credentials: true
}));

// ===== API AUTHENTICATION MIDDLEWARE =====

// API Authentication middleware
const isAuthenticatedAPI = (req, res, next) => {
  if (req.session.user) {
    next();
  } else {
    res.status(401).json({ success: false, error: 'Not authenticated' });
  }
};

// Admin role check middleware
const isAdminAPI = (req, res, next) => {
  if (req.session.user && req.session.user.role === 'admin') {
    next();
  } else {
    res.status(403).json({ success: false, error: 'Insufficient permissions' });
  }
};

// ===== HELPER FUNCTIONS =====

// Function to get dashboard data
async function getDashboardData(pool) {
  try {
    // Get total materials count
    const [materialCountResult] = await pool.query('SELECT COUNT(*) as count FROM materials');
    const totalMaterials = materialCountResult[0].count;
    
    // Get unique suppliers count
    const [supplierCountResult] = await pool.query('SELECT COUNT(DISTINCT supplier) as count FROM materials');
    const totalSuppliers = supplierCountResult[0].count;
    
    // Get recent updates (last 5 updated materials)
    const [recentMaterials] = await pool.query(
      'SELECT * FROM materials ORDER BY id DESC LIMIT 5'
    );
    
    // Get material types distribution
    const [materialTypes] = await pool.query(
      'SELECT part_name, COUNT(*) as count FROM materials GROUP BY part_name'
    );
    
    // Format data for charts
    const materialTypeLabels = materialTypes.map(type => type.part_name);
    const materialTypeData = materialTypes.map(type => type.count);
    
    // Mock data for inventory changes
    const inventoryChanges = {
      labels: ['Jan', 'Feb', 'Mar', 'Apr', 'May'],
      data: [42, 49, 55, 60, 66]
    };
    
    // Get system users count
    const [usersCountResult] = await pool.query('SELECT COUNT(*) as count FROM users');
    const systemUsers = usersCountResult[0].count;
    
    return {
      totalMaterials,
      totalSuppliers,
      recentMaterials,
      materialTypeLabels,
      materialTypeData,
      inventoryChanges,
      systemUsers,
      ordersThisWeek: 12 // This is still mock data, replace with actual query
    };
  } catch (error) {
    console.error('Error getting dashboard data:', error);
    throw error;
  }
}

// ===== API ROUTES =====

// Authentication API
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    // In a real application, you should hash passwords and compare hash
    const [rows] = await pool.query(
      'SELECT * FROM users WHERE username = ?',
      [username]
    );
    
    if (rows.length > 0 && password === rows[0].password) { // Simplified for demo
      req.session.user = {
        id: rows[0].id,
        username: rows[0].username,
        fullName: rows[0].full_name,
        role: rows[0].role
      };
      res.json({ 
        success: true, 
        user: req.session.user 
      });
    } else {
      res.status(401).json({ 
        success: false, 
        error: 'Invalid username or password' 
      });
    }
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ 
      success: false, 
      error: 'An error occurred during login' 
    });
  }
});

app.get('/api/auth/status', (req, res) => {
  if (req.session.user) {
    res.json({ 
      authenticated: true, 
      user: req.session.user 
    });
  } else {
    res.json({ 
      authenticated: false, 
      user: null 
    });
  }
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

// Dashboard API
app.get('/api/dashboard', isAuthenticatedAPI, async (req, res) => {
  try {
    const dashboardData = await getDashboardData(pool);
    res.json({
      success: true,
      ...dashboardData
    });
  } catch (error) {
    console.error('Error getting dashboard data:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to load dashboard data' 
    });
  }
});

// ===== USER MANAGEMENT API =====
// Get all users (admin only)
app.get('/api/users', isAuthenticatedAPI, isAdminAPI, async (req, res) => {
  try {
    // Don't return password in the response
    const [users] = await pool.query('SELECT id, username, full_name, role, phone FROM users ORDER BY id');
    res.json({ success: true, data: users });
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ success: false, error: 'Failed to fetch users' });
  }
});

// Get a specific user
app.get('/api/users/:id', isAuthenticatedAPI, async (req, res) => {
  try {
    const { id } = req.params;
    
    // Normal users can only get their own information, admins can get any user
    if (req.session.user.role !== 'admin' && req.session.user.id !== parseInt(id)) {
      return res.status(403).json({ success: false, error: 'Insufficient permissions' });
    }
    
    const [users] = await pool.query(
      'SELECT id, username, full_name, role, phone, created_at FROM users WHERE id = ?', 
      [id]
    );
    
    if (users.length === 0) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }
    
    res.json({ success: true, data: users[0] });
  } catch (error) {
    console.error('Error fetching user:', error);
    res.status(500).json({ success: false, error: 'Failed to fetch user' });
  }
});

// Create a new user (admin only)
app.post('/api/users', isAuthenticatedAPI, isAdminAPI, async (req, res) => {
  try {
    const { username, password, fullName, role, phone } = req.body;
    
    // Validate required fields
    if (!username || !password || !fullName || !role) {
      return res.status(400).json({ success: false, error: 'Missing required fields' });
    }
    
    // Check if username already exists
    const [existingUsers] = await pool.query('SELECT id FROM users WHERE username = ?', [username]);
    if (existingUsers.length > 0) {
      return res.status(400).json({ success: false, error: 'Username already exists' });
    }
    
    // In a real app, you would hash the password here
    // For simplicity, we're storing plain text passwords (not recommended for production!)
    const [result] = await pool.query(
      'INSERT INTO users (username, password, full_name, role, phone) VALUES (?, ?, ?, ?, ?)',
      [username, password, fullName, role, phone || null]
    );
    
    res.status(201).json({ 
      success: true, 
      message: 'User created successfully', 
      userId: result.insertId 
    });
  } catch (error) {
    console.error('Error creating user:', error);
    res.status(500).json({ success: false, error: 'Failed to create user' });
  }
});

// Update a user (admin only or self update)
app.put('/api/users/:id', isAuthenticatedAPI, async (req, res) => {
  try {
    const { id } = req.params;
    const { username, password, fullName, role, phone } = req.body;
    
    // Normal users can only update their own information, admins can update any user
    if (req.session.user.role !== 'admin' && req.session.user.id !== parseInt(id)) {
      return res.status(403).json({ success: false, error: 'Insufficient permissions' });
    }
    
    // Normal users cannot change their role
    if (req.session.user.role !== 'admin' && role && role !== req.session.user.role) {
      return res.status(403).json({ success: false, error: 'Cannot change role' });
    }
    
    // Check if user exists
    const [existingUser] = await pool.query('SELECT id FROM users WHERE id = ?', [id]);
    if (existingUser.length === 0) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }
    
    // Check if username exists (if changing username)
    if (username) {
      const [existingUsername] = await pool.query('SELECT id FROM users WHERE username = ? AND id != ?', [username, id]);
      if (existingUsername.length > 0) {
        return res.status(400).json({ success: false, error: 'Username already exists' });
      }
    }
    
    // Build the SQL update statement dynamically based on what's provided
    let updateFields = [];
    let queryParams = [];
    
    if (username) {
      updateFields.push('username = ?');
      queryParams.push(username);
    }
    
    if (password) {
      // In a real app, you would hash the password here
      updateFields.push('password = ?');
      queryParams.push(password);
    }
    
    if (fullName) {
      updateFields.push('full_name = ?');
      queryParams.push(fullName);
    }
    
    if (role && req.session.user.role === 'admin') {
      updateFields.push('role = ?');
      queryParams.push(role);
    }
    
    if (phone !== undefined) {
      updateFields.push('phone = ?');
      queryParams.push(phone);
    }
    
    // Add the ID at the end of params array
    queryParams.push(id);
    
    if (updateFields.length === 0) {
      return res.status(400).json({ success: false, error: 'No fields to update' });
    }
    
    const query = `UPDATE users SET ${updateFields.join(', ')} WHERE id = ?`;
    await pool.query(query, queryParams);
    
    res.json({ success: true, message: 'User updated successfully' });
  } catch (error) {
    console.error('Error updating user:', error);
    res.status(500).json({ success: false, error: 'Failed to update user' });
  }
});

// Delete a user (admin only)
app.delete('/api/users/:id', isAuthenticatedAPI, isAdminAPI, async (req, res) => {
  try {
    const { id } = req.params;
    
    // Prevent deleting the current user
    if (req.session.user.id === parseInt(id)) {
      return res.status(400).json({ success: false, error: 'Cannot delete yourself' });
    }
    
    // Check if user exists
    const [existingUser] = await pool.query('SELECT id FROM users WHERE id = ?', [id]);
    if (existingUser.length === 0) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }
    
    await pool.query('DELETE FROM users WHERE id = ?', [id]);
    
    res.json({ success: true, message: 'User deleted successfully' });
  } catch (error) {
    console.error('Error deleting user:', error);
    res.status(500).json({ success: false, error: 'Failed to delete user' });
  }
});

// ===== MATERIALS API =====

app.get('/api/materials', isAuthenticatedAPI, async (req, res) => {
  try {
    const [materials] = await pool.query('SELECT * FROM materials ORDER BY id DESC');
    res.json({ success: true, data: materials });
  } catch (error) {
    console.error('Error fetching materials:', error);
    res.status(500).json({ success: false, error: 'Failed to fetch materials' });
  }
});

app.post('/api/materials', isAuthenticatedAPI, async (req, res) => {
  try {
    const { packetNo, partName, length, width, height, quantity, supplier } = req.body;
    const currentDate = new Date().toLocaleDateString('en-GB');
    
    const [result] = await pool.query(
      `INSERT INTO materials 
       (packet_no, part_name, length, width, height, quantity, supplier, updated_by, last_updated) 
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [packetNo, partName, length, width, height, quantity, supplier, req.session.user.username, currentDate]
    );
    
    res.json({ 
      success: true, 
      message: 'Material added successfully', 
      id: result.insertId 
    });
  } catch (error) {
    console.error('Error adding material:', error);
    res.status(500).json({ success: false, error: 'Failed to add material' });
  }
});

app.put('/api/materials/:id', isAuthenticatedAPI, async (req, res) => {
  try {
    const { id } = req.params;
    const { packetNo, partName, length, width, height, quantity, supplier } = req.body;
    const currentDate = new Date().toLocaleDateString('en-GB');
    
    await pool.query(
      `UPDATE materials 
       SET packet_no = ?, part_name = ?, length = ?, width = ?, height = ?, 
           quantity = ?, supplier = ?, updated_by = ?, last_updated = ? 
       WHERE id = ?`,
      [packetNo, partName, length, width, height, quantity, supplier, 
       req.session.user.username, currentDate, id]
    );
    
    res.json({ success: true, message: 'Material updated successfully' });
  } catch (error) {
    console.error('Error updating material:', error);
    res.status(500).json({ success: false, error: 'Failed to update material' });
  }
});

app.delete('/api/materials/:id', isAuthenticatedAPI, async (req, res) => {
  try {
    const { id } = req.params;
    
    await pool.query('DELETE FROM materials WHERE id = ?', [id]);
    
    res.json({ success: true, message: 'Material deleted successfully' });
  } catch (error) {
    console.error('Error deleting material:', error);
    res.status(500).json({ success: false, error: 'Failed to delete material' });
  }
});

app.delete('/api/materials', isAuthenticatedAPI, async (req, res) => {
  try {
    const { ids } = req.body;
    
    if (!ids || !Array.isArray(ids) || ids.length === 0) {
      return res.status(400).json({ success: false, error: 'Invalid material IDs' });
    }
    
    const placeholders = ids.map(() => '?').join(',');
    await pool.query(`DELETE FROM materials WHERE id IN (${placeholders})`, ids);
    
    res.json({ success: true, message: 'Materials deleted successfully' });
  } catch (error) {
    console.error('Error deleting materials:', error);
    res.status(500).json({ success: false, error: 'Failed to delete materials' });
  }
});

// Get a single material by ID
app.get('/api/materials/:id', isAuthenticatedAPI, async (req, res) => {
  try {
    const { id } = req.params;
    
    const [rows] = await pool.query('SELECT * FROM materials WHERE id = ?', [id]);
    
    if (rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Material not found' });
    }
    
    res.json({ success: true, data: rows[0] });
  } catch (error) {
    console.error('Error fetching material:', error);
    res.status(500).json({ success: false, error: 'Failed to fetch material' });
  }
});

// UPDATE

// Employee Routes
app.get('/admin/human-resources', authenticateToken, (req, res) => {
    // Fetch employees with their nation names
    const query = `
      SELECT e.*, n.name as nation_name 
      FROM employees e
      LEFT JOIN nations n ON e.nation_id = n.id
      ORDER BY e.name ASC
    `;
    
    db.query(query, (err, results) => {
      if (err) {
        console.error('Error fetching employees:', err);
        return res.status(500).json({ message: 'Error fetching employees' });
      }
      res.status(200).json(results);
    });
  });
  
app.get('/admin/human-resources/:id', authenticateToken, (req, res) => {
    // Fetch employee with nation name
    const query = `
      SELECT e.*, n.name as nation_name 
      FROM employees e
      LEFT JOIN nations n ON e.nation_id = n.id
      WHERE e.id = ?
    `;
    
    db.query(query, [req.params.id], (err, results) => {
      if (err) {
        console.error('Error fetching employee:', err);
        return res.status(500).json({ message: 'Error fetching employee' });
      }
      if (results.length === 0) return res.status(404).json({ message: 'Employee not found' });
      res.status(200).json(results[0]);
    });
  });
  
// Get nations for dropdown
app.get('/admin/nations', authenticateToken, (req, res) => {
    db.query('SELECT id, name FROM nations ORDER BY name ASC', (err, results) => {
      if (err) {
        console.error('Error fetching nations:', err);
        return res.status(500).json({ message: 'Error fetching nations' });
      }
      res.status(200).json(results);
    });
  });
  
app.post('/admin/human-resources', authenticateToken, isAdmin, async (req, res) => {
    const { name, email, phone_number, address, date_of_birth, nation_id, position, salary, date_hire, other_nation } = req.body;
    
    // Kiểm tra các trường bắt buộc
    if (!name || !phone_number || !address || !date_of_birth || !position || !salary || !date_hire) {
      return res.status(400).json({ message: 'Required fields missing' });
    }
  
    try {
      // Xử lý nation_id nếu người dùng chọn "Other"
      let finalNationId = nation_id;
      
      if (other_nation && other_nation.trim() !== '') {
        // Kiểm tra xem nation đã tồn tại chưa
        db.query('SELECT id FROM nations WHERE name = ?', [other_nation], (err, results) => {
          if (err) {
            console.error('Error checking nation:', err);
            return res.status(500).json({ message: 'Error processing nation' });
          }
          
          if (results.length > 0) {
            // Nếu nation đã tồn tại, sử dụng id của nation đó
            finalNationId = results[0].id;
            insertEmployee(finalNationId);
          } else {
            // Nếu nation chưa tồn tại, tạo mới
            db.query('INSERT INTO nations (name) VALUES (?)', [other_nation], (err, result) => {
              if (err) {
                console.error('Error creating new nation:', err);
                return res.status(500).json({ message: 'Error creating new nation' });
              }
              finalNationId = result.insertId;
              insertEmployee(finalNationId);
            });
          }
        });
      } else {
        // Nếu không phải "Other", sử dụng nation_id đã chọn
        insertEmployee(finalNationId);
      }
      
      function insertEmployee(nationId) {
        // Thêm nhân viên mới vào cơ sở dữ liệu
        const query = `
          INSERT INTO employees 
          (name, email, phone_number, address, date_of_birth, nation_id, position, salary, date_hire) 
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        `;
        
        db.query(
          query,
          [name, email || null, phone_number, address, date_of_birth, nationId, position, salary, date_hire],
          (err, result) => {
            if (err) {
              console.error('Error adding employee:', err);
              return res.status(500).json({ message: 'Error adding employee' });
            }
            res.status(201).json({ message: 'Employee added successfully', employeeId: result.insertId });
          }
        );
      }
    } catch (error) {
      console.error('Error in employee creation:', error);
      res.status(500).json({ message: 'Error processing request' });
    }
  });
  
app.put('/admin/human-resources/:id', authenticateToken, isAdmin, (req, res) => {
    const { name, email, phone_number, address, date_of_birth, nation_id, position, salary, date_hire, other_nation } = req.body;
    
    // Kiểm tra các trường bắt buộc
    if (!name || !phone_number || !address || !date_of_birth || !position || !salary || !date_hire) {
      return res.status(400).json({ message: 'Required fields missing' });
    }
  
    try {
      // Xử lý nation_id nếu người dùng chọn "Other"
      let finalNationId = nation_id;
      
      if (other_nation && other_nation.trim() !== '') {
        // Kiểm tra xem nation đã tồn tại chưa
        db.query('SELECT id FROM nations WHERE name = ?', [other_nation], (err, results) => {
          if (err) {
            console.error('Error checking nation:', err);
            return res.status(500).json({ message: 'Error processing nation' });
          }
          
          if (results.length > 0) {
            // Nếu nation đã tồn tại, sử dụng id của nation đó
            finalNationId = results[0].id;
            updateEmployee(finalNationId);
          } else {
            // Nếu nation chưa tồn tại, tạo mới
            db.query('INSERT INTO nations (name) VALUES (?)', [other_nation], (err, result) => {
              if (err) {
                console.error('Error creating new nation:', err);
                return res.status(500).json({ message: 'Error creating new nation' });
              }
              finalNationId = result.insertId;
              updateEmployee(finalNationId);
            });
          }
        });
      } else {
        // Nếu không phải "Other", sử dụng nation_id đã chọn
        updateEmployee(finalNationId);
      }
      
      function updateEmployee(nationId) {
        // Cập nhật thông tin nhân viên
        const query = `
          UPDATE employees 
          SET name = ?, email = ?, phone_number = ?, address = ?, 
              date_of_birth = ?, nation_id = ?, position = ?, salary = ?, date_hire = ? 
          WHERE id = ?
        `;
        
        db.query(
          query,
          [name, email || null, phone_number, address, date_of_birth, nationId, position, salary, date_hire, req.params.id],
          (err, result) => {
            if (err) {
              console.error('Error updating employee:', err);
              return res.status(500).json({ message: 'Error updating employee' });
            }
            if (result.affectedRows === 0) return res.status(404).json({ message: 'Employee not found' });
            res.status(200).json({ message: 'Employee updated successfully' });
          }
        );
      }
    } catch (error) {
      console.error('Error in employee update:', error);
      res.status(500).json({ message: 'Error processing request' });
    }
  });
  
  app.delete('/admin/human-resources/:id', authenticateToken, isAdmin, (req, res) => {
    db.query('DELETE FROM employees WHERE id = ?', [req.params.id], (err, result) => {
      if (err) {
        console.error('Error deleting employee:', err);
        return res.status(500).json({ message: 'Error deleting employee' });
      }
      if (result.affectedRows === 0) return res.status(404).json({ message: 'Employee not found' });
      res.status(200).json({ message: 'Employee deleted successfully' });
    });
  });
// END UPDATE

// ===== SERVE REACT APP =====

// For React Single Page Application routes
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'client/build/index.html'));
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

module.exports = app;
