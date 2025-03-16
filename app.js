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

// UPDATE ================================>
// Modified update route
app.put('/api/materials/:id', isAuthenticatedAPI, async (req, res) => {
  try {
    const { id } = req.params;
    const { packetNo, partName, length, width, height, quantity, supplier } = req.body;
    
    // If user is admin, update directly
    if (req.session.user.role === 'admin') {
      const currentDate = new Date().toLocaleDateString('en-GB');
      
      await pool.query(
        `UPDATE materials 
         SET packet_no = ?, part_name = ?, length = ?, width = ?, height = ?, 
             quantity = ?, supplier = ?, updated_by = ?, last_updated = ? 
         WHERE id = ?`,
        [packetNo, partName, length, width, height, quantity, supplier, 
         req.session.user.username, currentDate, id]
      );
      
      return res.json({ success: true, message: 'Material updated successfully' });
    } else {
      // For regular users, create an update request
      const updatedData = {
        packet_no: packetNo,
        part_name: partName,
        length,
        width,
        height,
        quantity,
        supplier
      };
      
      const [result] = await pool.query(
        `INSERT INTO material_requests 
         (material_id, request_type, updated_data, requested_by, status, created_at) 
         VALUES (?, 'update', ?, ?, 'pending', NOW())`,
        [id, JSON.stringify(updatedData), req.session.user.id]
      );
      
      return res.json({
        success: true,
        message: 'Update request submitted for admin approval',
        requestId: result.insertId
      });
    }
  } catch (error) {
    console.error('Error updating material:', error);
    res.status(500).json({ success: false, error: 'Failed to update material' });
  }
});

// UPDATE ===================================>
// Modified delete route
app.delete('/api/materials/:id', isAuthenticatedAPI, async (req, res) => {
  try {
    const { id } = req.params;
    
    // If user is admin, delete directly
    if (req.session.user.role === 'admin') {
      await pool.query('DELETE FROM materials WHERE id = ?', [id]);
      return res.json({ success: true, message: 'Material deleted successfully' });
    } else {
      // For regular users, create a delete request
      const [result] = await pool.query(
        `INSERT INTO material_requests 
         (material_id, request_type, updated_data, requested_by, status, created_at) 
         VALUES (?, 'delete', '{}', ?, 'pending', NOW())`,
        [id, req.session.user.id]
      );
      
      return res.json({
        success: true,
        message: 'Delete request submitted for admin approval',
        requestId: result.insertId
      });
    }
  } catch (error) {
    console.error('Error deleting material:', error);
    res.status(500).json({ success: false, error: 'Failed to delete material' });
  }
});

// UPDATE ===================================>
// Modified bulk delete route
app.delete('/api/materials', isAuthenticatedAPI, async (req, res) => {
  try {
    const { ids } = req.body;
    
    if (!ids || !Array.isArray(ids) || ids.length === 0) {
      return res.status(400).json({ success: false, error: 'Invalid material IDs' });
    }
    
    // If user is admin, delete directly
    if (req.session.user.role === 'admin') {
      const placeholders = ids.map(() => '?').join(',');
      await pool.query(`DELETE FROM materials WHERE id IN (${placeholders})`, ids);
      
      return res.json({ success: true, message: 'Materials deleted successfully' });
    } else {
      // For regular users, create delete requests for each material
      const values = ids.map(id => [id, 'delete', '{}', req.session.user.id, 'pending', new Date()]);
      await pool.query(
        `INSERT INTO material_requests 
         (material_id, request_type, updated_data, requested_by, status, created_at) 
         VALUES ?`,
        [values]
      );
      
      return res.json({
        success: true,
        message: 'Delete requests submitted for admin approval'
      });
    }
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

// ===== SEARCH AND FILTER MATERIALS =====  HÂHHAHAHAHAHAHAHAAAAHHAHAHAA
app.get('/api/materials/search', isAuthenticatedAPI, async (req, res) => {
  try {
    const { searchTerm, filterBy } = req.query;
    
    // Validate filterBy is one of the allowed options
    const allowedFilters = ['packet_no', 'part_name', 'supplier', 'updated_by'];
    const filter = allowedFilters.includes(filterBy) ? filterBy : null;
    
    let query = 'SELECT * FROM materials WHERE 1=1';
    let queryParams = [];
    
    // Add search condition if searchTerm provided
    if (searchTerm && searchTerm.trim() !== '') {
      if (filter) {
        // Filter by specific column
        query += ` AND ${filter} LIKE ?`;
        queryParams.push(`%${searchTerm}%`);
      } else {
        // Search across all filterable columns if no specific filter
        query += ` AND (packet_no LIKE ? OR part_name LIKE ? OR supplier LIKE ? OR updated_by LIKE ?)`;
        queryParams.push(`%${searchTerm}%`, `%${searchTerm}%`, `%${searchTerm}%`, `%${searchTerm}%`);
      }
    }
    
    query += ' ORDER BY id DESC';
    
    const [materials] = await pool.query(query, queryParams);
    
    res.json({
      success: true,
      data: materials,
      filters: allowedFilters
    });
  } catch (error) {
    console.error('Error searching materials:', error);
    res.status(500).json({ success: false, error: 'Failed to search materials' });
  }
});

// ===== MATERIAL CHANGE REQUESTS API =====

// Create a request for material update or deletion
app.post('/api/material-requests', isAuthenticatedAPI, async (req, res) => {
  try {
    const { materialId, requestType, updatedData } = req.body;
    
    // Validate request type
    if (!['update', 'delete'].includes(requestType)) {
      return res.status(400).json({ success: false, error: 'Invalid request type' });
    }
    
    // Validate material exists
    const [materialExists] = await pool.query('SELECT id FROM materials WHERE id = ?', [materialId]);
    if (materialExists.length === 0) {
      return res.status(404).json({ success: false, error: 'Material not found' });
    }
    
    // For update requests, validate we have updated data
    if (requestType === 'update' && (!updatedData || Object.keys(updatedData).length === 0)) {
      return res.status(400).json({ success: false, error: 'No update data provided' });
    }
    
    // Insert the request into the database
    const [result] = await pool.query(
      `INSERT INTO material_requests 
       (material_id, request_type, updated_data, requested_by, status, created_at) 
       VALUES (?, ?, ?, ?, 'pending', NOW())`,
      [materialId, requestType, JSON.stringify(updatedData || {}), req.session.user.id]
    );
    
    res.status(201).json({
      success: true, 
      message: 'Request submitted successfully',
      requestId: result.insertId
    });
  } catch (error) {
    console.error('Error creating material request:', error);
    res.status(500).json({ success: false, error: 'Failed to submit request' });
  }
});

// Get all pending requests (admin only)
app.get('/api/material-requests', isAuthenticatedAPI, isAdminAPI, async (req, res) => {
  try {
    const [requests] = await pool.query(`
      SELECT r.*, m.packet_no, m.part_name, u.username as requested_by_username 
      FROM material_requests r
      JOIN materials m ON r.material_id = m.id
      JOIN users u ON r.requested_by = u.id
      WHERE r.status = 'pending'
      ORDER BY r.created_at DESC
    `);
    
    // Parse the updated_data JSON for each request
    const formattedRequests = requests.map(req => ({
      ...req,
      updated_data: JSON.parse(req.updated_data || '{}')
    }));
    
    res.json({ success: true, data: formattedRequests });
  } catch (error) {
    console.error('Error fetching material requests:', error);
    res.status(500).json({ success: false, error: 'Failed to fetch requests' });
  }
});

// Get user's own pending requests
app.get('/api/material-requests/my', isAuthenticatedAPI, async (req, res) => {
  try {
    const [requests] = await pool.query(`
      SELECT r.*, m.packet_no, m.part_name
      FROM material_requests r
      JOIN materials m ON r.material_id = m.id
      WHERE r.requested_by = ? AND r.status = 'pending'
      ORDER BY r.created_at DESC
    `, [req.session.user.id]);
    
    // Parse the updated_data JSON for each request
    const formattedRequests = requests.map(req => ({
      ...req,
      updated_data: JSON.parse(req.updated_data || '{}')
    }));
    
    res.json({ success: true, data: formattedRequests });
  } catch (error) {
    console.error('Error fetching user requests:', error);
    res.status(500).json({ success: false, error: 'Failed to fetch requests' });
  }
});

// Approve or reject a request (admin only)
app.put('/api/material-requests/:id', isAuthenticatedAPI, isAdminAPI, async (req, res) => {
  try {
    const { id } = req.params;
    const { status, comment } = req.body;
    
    // Validate status
    if (!['approved', 'rejected'].includes(status)) {
      return res.status(400).json({ success: false, error: 'Invalid status' });
    }
    
    // Start a transaction
    const connection = await pool.getConnection();
    await connection.beginTransaction();
    
    try {
      // Get the request details
      const [requests] = await connection.query(
        'SELECT * FROM material_requests WHERE id = ? AND status = "pending"',
        [id]
      );
      
      if (requests.length === 0) {
        await connection.rollback();
        return res.status(404).json({ success: false, error: 'Request not found or already processed' });
      }
      
      const request = requests[0];
      const updatedData = JSON.parse(request.updated_data || '{}');
      
      // Update the request status
      await connection.query(
        'UPDATE material_requests SET status = ?, processed_by = ?, processed_at = NOW(), comment = ? WHERE id = ?',
        [status, req.session.user.id, comment || null, id]
      );
      
      // If approved, apply the changes
      if (status === 'approved') {
        if (request.request_type === 'update') {
          // Build update query dynamically
          const fields = Object.keys(updatedData);
          if (fields.length > 0) {
            const updateFields = fields.map(field => `${field} = ?`).join(', ');
            const values = fields.map(field => updatedData[field]);
            
            // Add the updated_by and last_updated
            const currentDate = new Date().toLocaleDateString('en-GB');
            const query = `UPDATE materials SET ${updateFields}, updated_by = ?, last_updated = ? WHERE id = ?`;
            
            // Execute the update
            await connection.query(
              query,
              [...values, req.session.user.username, currentDate, request.material_id]
            );
          }
        } else if (request.request_type === 'delete') {
          // Execute the delete
          await connection.query('DELETE FROM materials WHERE id = ?', [request.material_id]);
        }
      }
      
      // Commit the transaction
      await connection.commit();
      
      res.json({
        success: true,
        message: `Request ${status === 'approved' ? 'approved and changes applied' : 'rejected'}`
      });
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  } catch (error) {
    console.error('Error processing request:', error);
    res.status(500).json({ success: false, error: 'Failed to process request' });
  }
});

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
