// app.js - Main Express application
const cors = require("cors");
const express = require("express");
const path = require("path");
const mysql = require("mysql2/promise");
const bodyParser = require("body-parser");
const session = require("express-session");
const app = express();
require("dotenv").config();
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
  queueLimit: 0,
});

// Middlewares
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, "public")));
app.use(
  session({
    secret: process.env.SESSION_SECRET || "inventory-management-secret-key",
    resave: false,
    saveUninitialized: true,
    cookie: { maxAge: 24 * 60 * 60 * 1000 },
  })
);

// CORS configuration
app.use(
  cors({
    origin: ["http://localhost:3001", "http://localhost:3000"],
    credentials: true,
  })
);

// ===== API AUTHENTICATION MIDDLEWARE =====

// API Authentication middleware
const isAuthenticatedAPI = (req, res, next) => {
  if (req.session.user) {
    next();
  } else {
    res.status(401).json({ success: false, error: "Not authenticated" });
  }
};

// Admin role check middleware
const isAdminAPI = (req, res, next) => {
  if (
    req.session.user &&
    (req.session.user.role === "admin" || req.session.user.role === "quản lý")
  ) {
    next();
  } else {
    res.status(403).json({ success: false, error: "Insufficient permissions" });
  }
};

// ===== HELPER FUNCTIONS =====

// Function to get dashboard data
async function getDashboardData(pool) {
  try {
    // Get total materials count
    const [materialCountResult] = await pool.query(
      "SELECT COUNT(*) as count FROM materials"
    );
    const totalMaterials = materialCountResult[0].count;

    // Get unique suppliers count
    const [supplierCountResult] = await pool.query(
      "SELECT COUNT(DISTINCT supplier) as count FROM materials"
    );
    const totalSuppliers = supplierCountResult[0].count;

    // Get recent updates (last 5 updated materials)
    const [recentMaterials] = await pool.query(
      "SELECT * FROM materials ORDER BY id DESC LIMIT 5"
    );

    // Get material types distribution
    const [materialTypes] = await pool.query(
      "SELECT part_name, COUNT(*) as count FROM materials GROUP BY part_name"
    );

    // Format data for charts
    const materialTypeLabels = materialTypes.map((type) => type.part_name);
    const materialTypeData = materialTypes.map((type) => type.count);

    // Mock data for inventory changes
    const inventoryChanges = {
      labels: ["Jan", "Feb", "Mar", "Apr", "May"],
      data: [42, 49, 55, 60, 66],
    };

    // Get system users count
    const [usersCountResult] = await pool.query(
      "SELECT COUNT(*) as count FROM users"
    );
    const systemUsers = usersCountResult[0].count;

    return {
      totalMaterials,
      totalSuppliers,
      recentMaterials,
      materialTypeLabels,
      materialTypeData,
      inventoryChanges,
      systemUsers,
      ordersThisWeek: 12, // This is still mock data, replace with actual query
    };
  } catch (error) {
    console.error("Error getting dashboard data:", error);
    throw error;
  }
}

// Add this function near the top of your app.js file
function safelyParseJSON(json) {
  try {
    // If it's already an object, return it
    if (typeof json === "object" && json !== null) {
      return json;
    }

    // If it's a string, parse it
    if (typeof json === "string") {
      return JSON.parse(json);
    }

    // Otherwise, return an empty object
    return {};
  } catch (error) {
    console.error("JSON parse error:", error);
    return {};
  }
}

// Then update your API route
// Trong file app.js, tìm route sau:
app.get("/api/material-requests", isAuthenticatedAPI, async (req, res) => {
  try {
    // Get request filter from query params
    const status = req.query.status || "pending";

    // Sửa phần này để bao gồm cả quản lý
    const whereClause =
      req.session.user.role === "admin" || req.session.user.role === "quản lý"
        ? "WHERE mr.status = ?"
        : "WHERE mr.status = ? AND mr.user_id = ?";

    const queryParams =
      req.session.user.role === "admin" || req.session.user.role === "quản lý"
        ? [status]
        : [status, req.session.user.id];

    // Query with joins to get user info
    const [requests] = await pool.query(
      `SELECT mr.*, u.username as user_username, u.full_name as user_full_name
       FROM material_requests mr
       JOIN users u ON mr.user_id = u.id
       ${whereClause}
       ORDER BY mr.request_date DESC`,
      queryParams
    );

    // Pre-process the request data to ensure it's properly formatted
    const processedRequests = requests.map((request) => {
      // Make a copy to avoid modifying the original
      const processedRequest = { ...request };

      // Process the request_data field
      if (processedRequest.request_data) {
        try {
          // Parse JSON string if needed
          processedRequest.request_data = safelyParseJSON(
            processedRequest.request_data
          );
        } catch (error) {
          console.error(
            `Error processing request data for ID ${request.id}:`,
            error
          );
          processedRequest.request_data = {};
        }
      }

      return processedRequest;
    });

    res.json({ success: true, data: processedRequests });
  } catch (error) {
    console.error("Error fetching material requests:", error);
    res
      .status(500)
      .json({ success: false, error: "Failed to fetch material requests" });
  }
});

// ===== API ROUTES =====

// Authentication API
app.post("/api/auth/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    // In a real application, you should hash passwords and compare hash
    const [rows] = await pool.query("SELECT * FROM users WHERE username = ?", [
      username,
    ]);

    if (rows.length > 0 && password === rows[0].password) {
      // Simplified for demo
      req.session.user = {
        id: rows[0].id,
        username: rows[0].username,
        fullName: rows[0].full_name,
        role: rows[0].role,
      };
      res.json({
        success: true,
        user: req.session.user,
      });
    } else {
      res.status(401).json({
        success: false,
        error: "Invalid username or password",
      });
    }
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({
      success: false,
      error: "An error occurred during login",
    });
  }
});

app.get("/api/auth/status", (req, res) => {
  if (req.session.user) {
    res.json({
      authenticated: true,
      user: req.session.user,
    });
  } else {
    res.json({
      authenticated: false,
      user: null,
    });
  }
});

app.post("/api/auth/logout", (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

// Dashboard API
app.get("/api/dashboard", isAuthenticatedAPI, async (req, res) => {
  try {
    const dashboardData = await getDashboardData(pool);
    res.json({
      success: true,
      ...dashboardData,
    });
  } catch (error) {
    console.error("Error getting dashboard data:", error);
    res.status(500).json({
      success: false,
      error: "Failed to load dashboard data",
    });
  }
});

// ===== USER MANAGEMENT API =====
// Get all users (admin only)
app.get("/api/users", isAuthenticatedAPI, isAdminAPI, async (req, res) => {
  try {
    // Don't return password in the response
    const [users] = await pool.query(
      "SELECT id, username, full_name, role, phone FROM users ORDER BY id"
    );
    res.json({ success: true, data: users });
  } catch (error) {
    console.error("Error fetching users:", error);
    res.status(500).json({ success: false, error: "Failed to fetch users" });
  }
});

// Get a specific user
app.get("/api/users/:id", isAuthenticatedAPI, async (req, res) => {
  try {
    const { id } = req.params;

    // Normal users can only get their own information, admins can get any user
    if (
      req.session.user.role !== "admin" &&
      req.session.user.id !== parseInt(id)
    ) {
      return res
        .status(403)
        .json({ success: false, error: "Insufficient permissions" });
    }

    const [users] = await pool.query(
      "SELECT id, username, full_name, role, phone, created_at FROM users WHERE id = ?",
      [id]
    );

    if (users.length === 0) {
      return res.status(404).json({ success: false, error: "User not found" });
    }

    res.json({ success: true, data: users[0] });
  } catch (error) {
    console.error("Error fetching user:", error);
    res.status(500).json({ success: false, error: "Failed to fetch user" });
  }
});

// Create a new user (admin only)
app.post("/api/users", isAuthenticatedAPI, isAdminAPI, async (req, res) => {
  try {
    const { username, password, fullName, role, phone } = req.body;

    // Validate required fields
    if (!username || !password || !fullName || !role) {
      return res
        .status(400)
        .json({ success: false, error: "Missing required fields" });
    }

    // Check if username already exists
    const [existingUsers] = await pool.query(
      "SELECT id FROM users WHERE username = ?",
      [username]
    );
    if (existingUsers.length > 0) {
      return res
        .status(400)
        .json({ success: false, error: "Username already exists" });
    }

    // In a real app, you would hash the password here
    // For simplicity, we're storing plain text passwords (not recommended for production!)
    const [result] = await pool.query(
      "INSERT INTO users (username, password, full_name, role, phone) VALUES (?, ?, ?, ?, ?)",
      [username, password, fullName, role, phone || null]
    );

    res.status(201).json({
      success: true,
      message: "User created successfully",
      userId: result.insertId,
    });
  } catch (error) {
    console.error("Error creating user:", error);
    res.status(500).json({ success: false, error: "Failed to create user" });
  }
});

// Update a user (admin only or self update)
app.put("/api/users/:id", isAuthenticatedAPI, async (req, res) => {
  try {
    const { id } = req.params;
    const { username, password, fullName, role, phone } = req.body;

    const isAdmin = req.session.user.role === "admin";
    const isManager = req.session.user.role === "quản lý";

    // Normal users can only update their own information
    // Admins can update any user
    // Managers can update any user except admins
    if (req.session.user.id !== parseInt(id) && !isAdmin && !isManager) {
      return res
        .status(403)
        .json({ success: false, error: "Insufficient permissions" });
    }

    // Check if user exists
    const [existingUserRows] = await pool.query(
      "SELECT id, role FROM users WHERE id = ?",
      [id]
    );
    if (existingUserRows.length === 0) {
      return res.status(404).json({ success: false, error: "User not found" });
    }

    const existingUser = existingUserRows[0];

    // Managers cannot modify admins
    if (isManager && !isAdmin && existingUser.role === "admin") {
      return res
        .status(403)
        .json({ success: false, error: "Managers cannot modify admin users" });
    }

    // Normal users cannot change their role
    if (!isAdmin && !isManager && role && role !== req.session.user.role) {
      return res
        .status(403)
        .json({ success: false, error: "Cannot change role" });
    }

    // Managers cannot set users to admin role
    if (isManager && !isAdmin && role === "admin") {
      return res
        .status(403)
        .json({ success: false, error: "Managers cannot assign admin role" });
    }

    // Check if username exists (if changing username)
    if (username) {
      const [existingUsername] = await pool.query(
        "SELECT id FROM users WHERE username = ? AND id != ?",
        [username, id]
      );
      if (existingUsername.length > 0) {
        return res
          .status(400)
          .json({ success: false, error: "Username already exists" });
      }
    }

    // Build the SQL update statement dynamically based on what's provided
    let updateFields = [];
    let queryParams = [];

    if (username) {
      updateFields.push("username = ?");
      queryParams.push(username);
    }

    if (password) {
      // In a real app, you would hash the password here
      updateFields.push("password = ?");
      queryParams.push(password);
    }

    if (fullName) {
      updateFields.push("full_name = ?");
      queryParams.push(fullName);
    }

    if (role && (isAdmin || isManager)) {
      updateFields.push("role = ?");
      queryParams.push(role);
    }

    if (phone !== undefined) {
      updateFields.push("phone = ?");
      queryParams.push(phone);
    }

    // Add the ID at the end of params array
    queryParams.push(id);

    if (updateFields.length === 0) {
      return res
        .status(400)
        .json({ success: false, error: "No fields to update" });
    }

    const query = `UPDATE users SET ${updateFields.join(", ")} WHERE id = ?`;
    await pool.query(query, queryParams);

    res.json({ success: true, message: "User updated successfully" });
  } catch (error) {
    console.error("Error updating user:", error);
    res.status(500).json({ success: false, error: "Failed to update user" });
  }
});

// Delete a user (admin only)
app.delete("/api/users/:id", isAuthenticatedAPI, async (req, res) => {
  try {
    const { id } = req.params;
    const isAdmin = req.session.user.role === "admin";
    const isManager = req.session.user.role === "quản lý";

    // Only admins and managers can delete users
    if (!isAdmin && !isManager) {
      return res
        .status(403)
        .json({ success: false, error: "Insufficient permissions" });
    }

    // Prevent deleting the current user
    if (req.session.user.id === parseInt(id)) {
      return res
        .status(400)
        .json({ success: false, error: "Cannot delete yourself" });
    }

    // Check if user exists and get their role
    const [existingUserRows] = await pool.query(
      "SELECT id, role FROM users WHERE id = ?",
      [id]
    );
    if (existingUserRows.length === 0) {
      return res.status(404).json({ success: false, error: "User not found" });
    }

    const existingUser = existingUserRows[0];

    // Managers cannot delete admins
    if (isManager && !isAdmin && existingUser.role === "admin") {
      return res
        .status(403)
        .json({ success: false, error: "Managers cannot delete admin users" });
    }

    await pool.query("DELETE FROM users WHERE id = ?", [id]);

    res.json({ success: true, message: "User deleted successfully" });
  } catch (error) {
    console.error("Error deleting user:", error);
    res.status(500).json({ success: false, error: "Failed to delete user" });
  }
});

// ===== MATERIALS API =====

app.get("/api/materials", isAuthenticatedAPI, async (req, res) => {
  try {
    const [materials] = await pool.query(
      "SELECT * FROM materials ORDER BY id DESC"
    );
    res.json({ success: true, data: materials });
  } catch (error) {
    console.error("Error fetching materials:", error);
    res
      .status(500)
      .json({ success: false, error: "Failed to fetch materials" });
  }
});

// Update these API endpoints in app.js

// Create new material with packet_no uniqueness validation
app.post("/api/materials", isAuthenticatedAPI, async (req, res) => {
  try {
    // Check if user is admin or manager
    const isAdmin = req.session.user.role === "admin";
    const isManager = req.session.user.role === "quản lý";

    if (!isAdmin && !isManager) {
      return res
        .status(403)
        .json({ success: false, error: "Insufficient permissions" });
    }
    const { packetNo, partName, length, width, height, quantity, supplier } =
      req.body;
    const currentDate = new Date().toLocaleDateString("en-GB");

    // Check if a material with the same packet_no already exists
    const [existingMaterials] = await pool.query(
      "SELECT id FROM materials WHERE packet_no = ?",
      [packetNo]
    );

    if (existingMaterials.length > 0) {
      return res.status(400).json({
        success: false,
        error:
          "A material with this packet number already exists. Packet numbers must be unique.",
      });
    }

    const [result] = await pool.query(
      `INSERT INTO materials 
       (packet_no, part_name, length, width, height, quantity, supplier, updated_by, last_updated) 
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        packetNo,
        partName,
        length,
        width,
        height,
        quantity,
        supplier,
        req.session.user.username,
        currentDate,
      ]
    );

    res.json({
      success: true,
      message: "Material added successfully",
      id: result.insertId,
    });
  } catch (error) {
    console.error("Error adding material:", error);
    res.status(500).json({ success: false, error: "Failed to add material" });
  }
});

// Update material with packet_no uniqueness validation
app.put("/api/materials/:id", isAuthenticatedAPI, async (req, res) => {
  try {
    const { id } = req.params;
    const { packetNo, partName, length, width, height, quantity, supplier } =
      req.body;
    const currentDate = new Date().toLocaleDateString("en-GB");

    // Check if any other material has the same packet_no (excluding the current material)
    const [existingMaterials] = await pool.query(
      "SELECT id FROM materials WHERE packet_no = ? AND id != ?",
      [packetNo, id]
    );

    if (existingMaterials.length > 0) {
      return res.status(400).json({
        success: false,
        error:
          "Another material with this packet number already exists. Packet numbers must be unique.",
      });
    }

    await pool.query(
      `UPDATE materials 
       SET packet_no = ?, part_name = ?, length = ?, width = ?, height = ?, 
           quantity = ?, supplier = ?, updated_by = ?, last_updated = ? 
       WHERE id = ?`,
      [
        packetNo,
        partName,
        length,
        width,
        height,
        quantity,
        supplier,
        req.session.user.username,
        currentDate,
        id,
      ]
    );
    res.json({ success: true, message: "Material updated successfully" });
  } catch (error) {
    console.error("Error updating material:", error);
    res
      .status(500)
      .json({ success: false, error: "Failed to update material" });
  }
});

app.delete("/api/materials/:id", isAuthenticatedAPI, async (req, res) => {
  try {
    const { id } = req.params;

    await pool.query("DELETE FROM materials WHERE id = ?", [id]);

    res.json({ success: true, message: "Material deleted successfully" });
  } catch (error) {
    console.error("Error deleting material:", error);
    res
      .status(500)
      .json({ success: false, error: "Failed to delete material" });
  }
});

app.delete("/api/materials", isAuthenticatedAPI, async (req, res) => {
  try {
    const { ids } = req.body;

    if (!ids || !Array.isArray(ids) || ids.length === 0) {
      return res
        .status(400)
        .json({ success: false, error: "Invalid material IDs" });
    }

    const placeholders = ids.map(() => "?").join(",");
    await pool.query(
      `DELETE FROM materials WHERE id IN (${placeholders})`,
      ids
    );

    res.json({ success: true, message: "Materials deleted successfully" });
  } catch (error) {
    console.error("Error deleting materials:", error);
    res
      .status(500)
      .json({ success: false, error: "Failed to delete materials" });
  }
});

// Get a single material by ID
app.get("/api/materials/:id", isAuthenticatedAPI, async (req, res) => {
  try {
    const { id } = req.params;

    const [rows] = await pool.query("SELECT * FROM materials WHERE id = ?", [
      id,
    ]);

    if (rows.length === 0) {
      return res
        .status(404)
        .json({ success: false, error: "Material not found" });
    }

    res.json({ success: true, data: rows[0] });
  } catch (error) {
    console.error("Error fetching material:", error);
    res.status(500).json({ success: false, error: "Failed to fetch material" });
  }
});

// ===== MATERIAL REQUESTS API =====

// Get all material requests (admin only, with proper error handling)
app.get("/api/material-requests", isAuthenticatedAPI, async (req, res) => {
  try {
    // Get request filter from query params
    const status = req.query.status || "pending";

    // Admins see all requests, regular users only see their own
    const whereClause =
      req.session.user.role === "admin"
        ? "WHERE mr.status = ?"
        : "WHERE mr.status = ? AND mr.user_id = ?";

    const queryParams =
      req.session.user.role === "admin"
        ? [status]
        : [status, req.session.user.id];

    // Query with joins to get user info
    const [requests] = await pool.query(
      `SELECT mr.*, u.username as user_username, u.full_name as user_full_name
       FROM material_requests mr
       JOIN users u ON mr.user_id = u.id
       ${whereClause}
       ORDER BY mr.request_date DESC`,
      queryParams
    );

    // Log the retrieved data for debugging
    console.log(`Retrieved ${requests.length} ${status} material requests`);

    res.json({ success: true, data: requests });
  } catch (error) {
    console.error("Error fetching material requests:", error);
    res
      .status(500)
      .json({ success: false, error: "Failed to fetch material requests" });
  }
});

// Get material requests for current user
app.get("/api/my-material-requests", isAuthenticatedAPI, async (req, res) => {
  try {
    const [requests] = await pool.query(
      `SELECT * FROM material_requests
       WHERE user_id = ?
       ORDER BY request_date DESC`,
      [req.session.user.id]
    );

    console.log(
      `Retrieved ${requests.length} material requests for user ${req.session.user.id}`
    );

    res.json({ success: true, data: requests });
  } catch (error) {
    console.error("Error fetching user material requests:", error);
    res
      .status(500)
      .json({ success: false, error: "Failed to fetch material requests" });
  }
});

// Create a new material request (simplified)
app.post("/api/material-requests", isAuthenticatedAPI, async (req, res) => {
  try {
    console.log("Received material request payload:", JSON.stringify(req.body));

    const { requestType, materialId, requestData } = req.body;

    // Validate request type
    if (!["add", "edit", "delete"].includes(requestType)) {
      return res
        .status(400)
        .json({ success: false, error: "Invalid request type" });
    }

    // For edit and delete, materialId is required
    if ((requestType === "edit" || requestType === "delete") && !materialId) {
      return res.status(400).json({
        success: false,
        error: "Material ID is required for edit/delete requests",
      });
    }

    // Insert request into database
    const [result] = await pool.query(
      `INSERT INTO material_requests 
       (request_type, material_id, request_data, user_id) 
       VALUES (?, ?, ?, ?)`,
      [
        requestType,
        materialId || null,
        JSON.stringify(requestData || {}),
        req.session.user.id,
      ]
    );

    console.log(`Created material request with ID ${result.insertId}`);

    // Create notification for all admins
    const [admins] = await pool.query(
      'SELECT id FROM users WHERE role = "admin"'
    );

    for (const admin of admins) {
      await pool.query(
        `INSERT INTO admin_notifications (user_id, message)
         VALUES (?, ?)`,
        [
          admin.id,
          `New ${requestType} material request from ${req.session.user.username}`,
        ]
      );
    }

    res.status(201).json({
      success: true,
      message: "Material request submitted successfully",
      requestId: result.insertId,
    });
  } catch (error) {
    console.error("Error creating material request:", error);
    res.status(500).json({
      success: false,
      error: `Failed to create material request: ${error.message}`,
    });
  }
});

// Process a material request (admin only)
app.put(
  "/api/material-requests/:id",
  isAuthenticatedAPI,
  isAdminAPI,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { status, adminNotes } = req.body;

      console.log(`Processing material request ${id} with status ${status}`);

      // Validate status
      if (!["approved", "rejected"].includes(status)) {
        return res
          .status(400)
          .json({ success: false, error: "Invalid status" });
      }

      // Get the request details
      const [requests] = await pool.query(
        "SELECT * FROM material_requests WHERE id = ?",
        [id]
      );

      if (requests.length === 0) {
        return res
          .status(404)
          .json({ success: false, error: "Request not found" });
      }

      const request = requests[0];

      // Check if request is already processed
      if (request.status !== "pending") {
        return res
          .status(400)
          .json({ success: false, error: "Request already processed" });
      }

      let requestData = {};
      try {
        requestData = safelyParseJSON(request.request_data);
      } catch (error) {
        console.error("Error parsing request data:", error);
        return res
          .status(400)
          .json({ success: false, error: "Invalid request data format" });
      }

      // Start a transaction
      const connection = await pool.getConnection();
      await connection.beginTransaction();

      try {
        // Update request status
        await connection.query(
          `UPDATE material_requests 
         SET status = ?, response_date = NOW(), admin_id = ?, admin_notes = ? 
         WHERE id = ?`,
          [status, req.session.user.id, adminNotes || null, id]
        );

        console.log(`Updated material request ${id} status to ${status}`);

        // If approved, process the request
        if (status === "approved") {
          let requestData = {};
          try {
            requestData = safelyParseJSON(request.request_data);
          } catch (error) {
            console.error("Error parsing request data:", error);
            return res
              .status(400)
              .json({ success: false, error: "Invalid request data format" });
          }

          if (request.request_type === "add") {
            // Add new material
            const {
              packetNo,
              partName,
              length,
              width,
              height,
              quantity,
              supplier,
            } = requestData;
            const currentDate = new Date().toLocaleDateString("en-GB");

            // Check if a material with the same packet_no already exists
            const [existingMaterials] = await connection.query(
              "SELECT id FROM materials WHERE packet_no = ?",
              [packetNo]
            );

            if (existingMaterials.length > 0) {
              await connection.rollback();
              return res.status(400).json({
                success: false,
                error:
                  "A material with this packet number already exists. The request cannot be approved.",
              });
            }

            const [addResult] = await connection.query(
              `INSERT INTO materials 
             (packet_no, part_name, length, width, height, quantity, supplier, updated_by, last_updated) 
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
              [
                packetNo,
                partName,
                length,
                width,
                height,
                quantity,
                supplier,
                req.session.user.username,
                currentDate,
              ]
            );

            console.log(`Added new material with ID ${addResult.insertId}`);
          } else if (request.request_type === "edit") {
            // Edit existing material
            const {
              packetNo,
              partName,
              length,
              width,
              height,
              quantity,
              supplier,
            } = requestData;
            const currentDate = new Date().toLocaleDateString("en-GB");

            // Check if any other material has the same packet_no (excluding the current material)
            const [existingMaterials] = await connection.query(
              "SELECT id FROM materials WHERE packet_no = ? AND id != ?",
              [packetNo, request.material_id]
            );

            if (existingMaterials.length > 0) {
              await connection.rollback();
              return res.status(400).json({
                success: false,
                error:
                  "Another material with this packet number already exists. The request cannot be approved.",
              });
            }

            await connection.query(
              `UPDATE materials 
             SET packet_no = ?, part_name = ?, length = ?, width = ?, height = ?, 
                 quantity = ?, supplier = ?, updated_by = ?, last_updated = ? 
             WHERE id = ?`,
              [
                packetNo,
                partName,
                length,
                width,
                height,
                quantity,
                supplier,
                req.session.user.username,
                currentDate,
                request.material_id,
              ]
            );

            console.log(`Updated material ${request.material_id}`);
          } else if (request.request_type === "delete") {
            // Delete material
            await connection.query("DELETE FROM materials WHERE id = ?", [
              request.material_id,
            ]);
            console.log(`Deleted material ${request.material_id}`);
          }
        }

        // Commit the transaction
        await connection.commit();

        // Create notification for the requester
        await pool.query(
          `INSERT INTO admin_notifications (user_id, message)
         VALUES (?, ?)`,
          [
            request.user_id,
            `Your ${request.request_type} material request has been ${status}`,
          ]
        );

        res.json({
          success: true,
          message: `Request ${status} successfully`,
          requestId: id,
        });
      } catch (error) {
        // If error, rollback changes
        await connection.rollback();
        throw error;
      } finally {
        connection.release();
      }
    } catch (error) {
      console.error("Error processing material request:", error);
      res.status(500).json({
        success: false,
        error: `Failed to process material request: ${error.message}`,
      });
    }
  }
);

// ===== SERVE REACT APP =====

// For React Single Page Application routes
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "client/build/index.html"));
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

module.exports = app;
