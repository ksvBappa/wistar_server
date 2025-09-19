const express = require('express');
const multer = require('multer');
const path = require('path');
const cors = require('cors');
const bodyParser = require('body-parser');
const mysql = require('mysql2/promise'); // Using promise-based mysql2
require('dotenv').config();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
// const admin = require('./routes/Auth/adminRoutes');
const authenticateToken = require('./middlewares/AuthenticateToken');
const User = require('./models/Auth/adminModel');
const crypto = require('crypto');
const axios = require('axios');
const querystring = require("querystring");
const admin = require('./firebase');
// const fs = require('fs');
const fs = require('fs/promises');
const fsSync = require('fs');
const XLSX = require('xlsx');

const MERCHANT_ID = 'PGTESTPAYUAT86';
const SALT_KEY = '96434309-7796-489d-8924-ab56988a6076';
const SALT_INDEX = '1';
const PAYMENT_URL = 'https://api-preprod.phonepe.com/apis/pg-sandbox/pg/v1/pay';
const CALLBACK_URL = 'http://localhost:5000/api/payment/callback'; // Replace with ngrok URL






const app = express();



// Create upload directories if they don't exist
const uploadDirs = [
  'Uploads',
  'Uploads/images',
  'Uploads/videos',
  'Uploads/documents'
];
uploadDirs.forEach(dir => {
  if (!fsSync.existsSync(dir)) {
    fsSync.mkdirSync(dir, { recursive: true });
    console.log(`Created directory: ${dir}`);
  }
});


// Middleware
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use('/uploads', express.static(path.join(__dirname, 'Uploads')));

// Multer Config for Uploading Files
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const isImage = file.mimetype.startsWith('image/');
    const isVideo = file.mimetype.startsWith('video/');
    const isExcelOrCsv = [
      'text/csv',
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      'application/vnd.ms-excel'
    ].includes(file.mimetype);
    const destination = isImage ? 'Uploads/images' : isVideo ? 'Uploads/videos' : 'Uploads/documents';
    cb(null, destination);
  },
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`);
  },
});

const upload = multer({
  storage,
  fileFilter: (req, file, cb) => {
    const allowedTypes = [
      'image/jpeg',
      'image/png',
      'video/mp4',
      'application/pdf',
      'text/csv',
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      'application/vnd.ms-excel'
    ];
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error(`Invalid file type. Only ${allowedTypes.join(', ')} are allowed.`));
    }
  },
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
});

// Database Connection (lib/db.js)
const db = require('./lib/db'); // Ensure this is a mysql2/promise db

// Import Routes
const auth = require('./routes/Auth/authRoutes');
const { Console } = require('console');

// API Routes
app.use('/api/auth', auth);

// Helper function to handle errors
const handleError = (res, err, message = 'Server error') => {
  console.error(message, err.stack || err);
  res.status(500).json({ error: message });
};


// Login endpoint
app.post('/api/admin/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    // Validate request body
    if (!username || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    // Find admin in database
    const [rows] = await db.query(`SELECT * FROM user_table WHERE user_email = "${username}"`);
    const admin = rows[0];

    if (!admin) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Verify password
    const isPasswordValid = await bcrypt.compare(password, admin.user_password);
    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Generate JWT token
    const token = jwt.sign({ user_email: admin.user_email, role: 'admin' }, process.env.JWT_SECRET, {
      expiresIn: '1h',
    });

    res.json({ message: 'Login successful', token });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});


// GET all banners
app.get('/api/banners', async (req, res) => {
  try {
    const [rows] = await db.query('SELECT * FROM banners ORDER BY display_order ASC');
    res.json(rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// GET a single banner by ID
app.get('/api/banners/:id', async (req, res) => {
  try {
    const [rows] = await db.query('SELECT * FROM banners WHERE id = ?', [req.params.id]);
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Banner not found' });
    }
    res.json(rows[0]);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// POST a new banner
app.post('/api/banners', async (req, res) => {
  const { title, image_url, status, description, link, display_order } = req.body;
  if (!title || !image_url) {
    return res.status(400).json({ error: 'Title and image_url are required' });
  }
  try {
    const [result] = await db.query(
      'INSERT INTO banners (title, image_url, status, description, link, display_order) VALUES (?, ?, ?, ?, ?, ?)',
      [title, image_url, status || 'inactive', description, link, display_order || 0]
    );
    res.status(201).json({ id: result.insertId, ...req.body });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// PUT update a banner by ID
app.put('/api/banners/:id', async (req, res) => {
  const { title, image_url, status, description, link, display_order } = req.body;
  try {
    const [result] = await db.query(
      'UPDATE banners SET title = ?, image_url = ?, status = ?, description = ?, link = ?, display_order = ? WHERE id = ?',
      [title, image_url, status, description, link, display_order, req.params.id]
    );
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Banner not found' });
    }
    res.json({ message: 'Banner updated successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// DELETE a banner by ID
app.delete('/api/banners/:id', async (req, res) => {
  try {
    const [result] = await db.query('DELETE FROM banners WHERE id = ?', [req.params.id]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Banner not found' });
    }
    res.json({ message: 'Banner deleted successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// GET all self-promotion banners
app.get('/api/self-promo-banners', async (req, res) => {
  try {
    const [rows] = await db.query('SELECT * FROM self_promo_banners ORDER BY position ASC');
    res.json(rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// GET a single banner by ID
app.get('api/self-promo-banners/:id', async (req, res) => {
  try {
    const [rows] = await db.query('SELECT * FROM self_promo_banners WHERE id = ?', [req.params.id]);
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Banner not found' });
    }
    res.json(rows[0]);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// POST a new banner
app.post('api/self-promo-banners', async (req, res) => {
  const { title, image_url, status, description, link, position, start_date, end_date, target_audience } = req.body;
  if (!title || !image_url || !position) {
    return res.status(400).json({ error: 'Title, image_url, and position are required' });
  }
  try {
    const [result] = await db.query(
      'INSERT INTO self_promo_banners (title, image_url, status, description, link, position, start_date, end_date, target_audience, impressions, clicks) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0)',
      [title, image_url, status || 'inactive', description, link, position, start_date, end_date, target_audience]
    );
    res.status(201).json({ id: result.insertId, ...req.body, impressions: 0, clicks: 0 });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// PUT update a banner by ID
app.put('api/self-promo-banners/:id', async (req, res) => {
  const { title, image_url, status, description, link, position, start_date, end_date, target_audience, impressions, clicks } = req.body;
  try {
    const [result] = await db.query(
      'UPDATE self_promo_banners SET title = ?, image_url = ?, status = ?, description = ?, link = ?, position = ?, start_date = ?, end_date = ?, target_audience = ?, impressions = ?, clicks = ? WHERE id = ?',
      [title, image_url, status, description, link, position, start_date, end_date, target_audience, impressions || 0, clicks || 0, req.params.id]
    );
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Banner not found' });
    }
    res.json({ message: 'Banner updated successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// DELETE a banner by ID
app.delete('api/self-promo-banners/:id', async (req, res) => {
  try {
    const [result] = await db.query('DELETE FROM self_promo_banners WHERE id = ?', [req.params.id]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Banner not found' });
    }
    res.json({ message: 'Banner deleted successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// POST to increment impressions
app.post('api/self-promo-banners/:id/impressions', async (req, res) => {
  try {
    const [result] = await db.query('UPDATE self_promo_banners SET impressions = impressions + 1 WHERE id = ?', [req.params.id]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Banner not found' });
    }
    res.json({ message: 'Impressions incremented' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// POST to increment clicks
app.post('api/self-promo-banners/:id/clicks', async (req, res) => {
  try {
    const [result] = await db.query('UPDATE self_promo_banners SET clicks = clicks + 1 WHERE id = ?', [req.params.id]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Banner not found' });
    }
    res.json({ message: 'Clicks incremented' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});


app.get('/api/ecommerce-metrics', async (req, res) => {
  try {
    const [totalSales] = await db.query(
      'SELECT SUM(amount_due) as total FROM user_orders WHERE order_status = "delivered"'
    );
    const [totalOrders] = await db.query('SELECT COUNT(*) as total FROM user_orders');
    const [totalCustomers] = await db.query('SELECT COUNT(*) as total FROM user_table');
    const [monthlyRevenue] = await db.query(
      'SELECT SUM(amount_due) as total FROM user_orders WHERE order_status = "delivered" AND MONTH(order_date) = MONTH(CURDATE()) AND YEAR(order_date) = YEAR(CURDATE())'
    );
    res.json({
      totalSales: parseFloat(totalSales[0].total) || 0,
      totalOrders: totalOrders[0].total || 0,
      totalCustomers: totalCustomers[0].total || 0,
      monthlyRevenue: parseFloat(monthlyRevenue[0].total) || 0,
    });
  } catch (err) {
    console.error('Error fetching metrics:', err);
    res.status(500).json({ error: 'Error fetching metrics' });
  }
});

app.get('/api/monthly-sales', async (req, res) => {
  try {
    const [results] = await db.query(`
      SELECT MONTHNAME(order_date) as month, SUM(amount_due) as sales
      FROM user_orders
      WHERE YEAR(order_date) = YEAR(CURDATE()) AND order_status = 'delivered'
      GROUP BY MONTH(order_date)
      ORDER BY MONTH(order_date)
    `);
    res.json(results.map(row => ({
      month: row.month,
      sales: parseFloat(row.sales) || 0,
    })));
  } catch (err) {
    console.error('Error fetching monthly sales:', err);
    res.status(500).json({ error: 'Error fetching monthly sales' });
  }
});

app.get('/api/order-statistics', async (req, res) => {
  try {
    const [results] = await db.query(`
      SELECT order_status as status, COUNT(*) as count
      FROM user_orders
      GROUP BY order_status
    `);
    res.json(results.map(row => ({
      status: row.status,
      count: row.count,
    })));
  } catch (err) {
    console.error('Error fetching order statistics:', err);
    res.status(500).json({ error: 'Error fetching order statistics' });
  }
});

app.get('/api/monthly-target', async (req, res) => {
  try {
    const target = 100000; // Example fixed target
    const [sales] = await db.query(`
      SELECT SUM(amount_due) as total
      FROM user_orders
      WHERE order_status = 'delivered' AND MONTH(order_date) = MONTH(CURDATE()) AND YEAR(order_date) = YEAR(CURDATE())
    `);
    res.json({
      target,
      currentSales: parseFloat(sales[0].total) || 0,
      percentage: ((parseFloat(sales[0].total) || 0) / target * 100).toFixed(2),
    });
  } catch (err) {
    console.error('Error fetching monthly target:', err);
    res.status(500).json({ error: 'Error fetching monthly target' });
  }
});

app.get('/api/demographics', async (req, res) => {
  try {
    // Since user_table lacks age/gender, use user_address for a simple demographic
    const [locationDist] = await db.query(`
      SELECT user_address as location, COUNT(*) as count
      FROM user_table
      GROUP BY user_address
    `);
    res.json({
      locationDistribution: locationDist.map(row => ({ location: row.location || 'Unknown', count: row.count })),
    });
  } catch (err) {
    console.error('Error fetching demographics:', err);
    res.status(500).json({ error: 'Error fetching demographics' });
  }
});

app.get('/api/recent-orders', async (req, res) => {
  try {
    const [results] = await db.query(`
      SELECT 
        o.order_id,
        u.username as customer_name,
        o.amount_due as total_amount,
        o.order_status as status,
        o.order_date
      FROM user_orders o
      JOIN user_table u ON o.user_id = u.user_id
      ORDER BY o.order_date DESC
      LIMIT 5
    `);
    res.json(results.map(row => ({
      order_id: row.order_id,
      customer_name: row.customer_name,
      total_amount: parseFloat(row.total_amount),
      status: row.status,
      order_date: row.order_date,
    })));
  } catch (err) {
    console.error('Error fetching recent orders:', err);
    res.status(500).json({ error: 'Error fetching recent orders' });
  }
});


// --- Billing APIs ---
app.get('/api/billing/:user_id', async (req, res) => {
  try {
    const { user_id } = req.params;
    console.log(user_id);

    const [results] = await db.query(
      'SELECT * FROM billing WHERE user_id = ?',
      { replacements: [user_id] }
    );

    // console.log("results");
    // console.log(results);
    res.json(results);
  } catch (err) {
    handleError(res, err, 'Error fetching billing records');
  }
});


app.get('/api/billing', async (req, res) => {
  try {
    const [results] = await db.query('SELECT * FROM billing');
    res.json(results);
  } catch (err) {
    handleError(res, err, 'Error fetching billing records');
  }
});

app.post('/api/billing', async (req, res) => {
  const { user_id, name, lastname, contact, email, add1, add2, pin, city, state, country, gst_number, is_default } = req.body;
  try {
    await db.query(
      'INSERT INTO billing (user_id, name, lastname, contact, email, add1, add2, pin, city, state, country, gst_number, is_default) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      {
        replacements: [
          user_id, name, lastname, contact, email,
          add1, add2, pin, city, state, country,
          gst_number, is_default ? 1 : 0
        ],
        type: db.QueryTypes.INSERT,
      }
    );
    res.status(201).json({ message: 'Billing record created' });
  } catch (err) {
    console.error('SQL Error:', err);
    handleError(res, err, 'Error creating billing record');
  }
});


app.put('/api/billing/:id', async (req, res) => {
  const { id } = req.params;
  const { user_id, name, lastname, contact, email, add1, add2, pin, city, state, country, gst_number, is_default } = req.body;
  try {
    await db.query(
      'UPDATE billing SET user_id = ?, name = ?, lastname = ?, contact = ?, email = ?, add1 = ?, add2 = ?, pin = ?, city = ?, state = ?, country = ?, gst_number = ?, is_default = ? WHERE id = ?',
      [user_id, name, lastname, contact, email, add1, add2, pin, city, state, country, gst_number, is_default, id]
    );
    res.json({ message: 'Billing record updated' });
  } catch (err) {
    handleError(res, err, 'Error updating billing record');
  }
});

app.delete('/api/billing/:id', async (req, res) => {
  const { id } = req.params;
  try {
    await db.query('DELETE FROM billing WHERE id = ?', [id]);
    res.json({ message: 'Billing record deleted' });
  } catch (err) {
    handleError(res, err, 'Error deleting billing record');
  }
});

// --- Brands APIs ---
app.get('/api/brands', async (req, res) => {
  try {
    const [results] = await db.query('SELECT * FROM brands');
    res.json(results);
  } catch (err) {
    handleError(res, err, 'Error fetching brands');
  }
});

app.post('/api/brands', upload.single('brand_img'), async (req, res) => {
  const { brand_title, slug, title, description } = req.body;
  const brand_img = req.file ? `/uploads/images/${req.file.filename}` : null;
  try {
    await db.query(
      'INSERT INTO brands (brand_title, brand_img, slug, title, description) VALUES (?, ?, ?, ?, ?)',
      [brand_title, brand_img, slug, title, description]
    );
    res.status(201).json({ message: 'Brand created' });
  } catch (err) {
    handleError(res, err, 'Error creating brand');
  }
});

app.put('/api/brands/:id', upload.single('brand_img'), async (req, res) => {
  const { id } = req.params;
  const { brand_title, slug, title, description } = req.body;
  const brand_img = req.file ? `/uploads/images/${req.file.filename}` : null;
  try {
    await db.query(
      'UPDATE brands SET bprand_title = ?, brand_img = COALESCE(?, brand_img), slug = ?, title = ?, description = ? WHERE brand_id = ?',
      [brand_title, brand_img, slug, title, description, id]
    );
    res.json({ message: 'Brand updated' });
  } catch (err) {
    handleError(res, err, 'Error updating brand');
  }
});

app.delete('/api/brands/:id', async (req, res) => {
  const { id } = req.params;
  try {
    await db.query('DELETE FROM brands WHERE brand_id = ?', [id]);
    res.json({ message: 'Brand deleted' });
  } catch (err) {
    handleError(res, err, 'Error deleting brand');
  }
});

// --- Categories APIs ---
app.get('/api/categories', async (req, res) => {
  try {
    const [results] = await db.query('SELECT * FROM categories');
    res.json(results);
  } catch (err) {
    handleError(res, err, 'Error fetching categories');
  }
});

app.post('/api/categories', async (req, res) => {
  const { category_title, cat_slug, cat_title, cat_description } = req.body;
  try {
    await db.query(
      'INSERT INTO categories (category_title, cat_slug, cat_title, cat_description) VALUES (?, ?, ?, ?)',
      [category_title, cat_slug, cat_title, cat_description]
    );
    res.status(201).json({ message: 'Category created' });
  } catch (err) {
    handleError(res, err, 'Error creating category');
  }
});

app.put('/api/categories/:id', async (req, res) => {
  const { id } = req.params;
  const { category_title, cat_slug, cat_title, cat_description } = req.body;
  try {
    await db.query(
      'UPDATE categories SET category_title = ?, cat_slug = ?, cat_title = ?, cat_description = ? WHERE category_id = ?',
      [category_title, cat_slug, cat_title, cat_description, id]
    );
    res.json({ message: 'Category updated' });
  } catch (err) {
    handleError(res, err, 'Error updating category');
  }
});

app.delete('/api/categories/:id', async (req, res) => {
  const { id } = req.params;
  try {
    await db.query('DELETE FROM categories WHERE category_id = :id', {
      replacements: { id },
      type: db.QueryTypes.DELETE
    });
    res.json({ message: 'Category deleted' });
  } catch (err) {
    handleError(res, err, 'Error deleting category');
  }
});


// API endpoint for Excel upload
app.post('/api/upload-products-excel', upload.single('excel_file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    // Read the Excel file
    const workbook = XLSX.readFile(req.file.path);
    const sheetName = workbook.SheetNames[0];
    const worksheet = workbook.Sheets[sheetName];
    const rows = XLSX.utils.sheet_to_json(worksheet, { header: 1 });
    console.log('Parsed Excel rows:', rows); // Debug: Log all rows

    // Validate headers
    const expectedHeaders = [
      'product_title', 'product_description', 'product_keywords', 'category_id', 'brand_id',
      'product_image1', 'product_image2', 'product_image3', 'product_image4', 'product_video',
      'product_price', 'discount_percentage', 'selling_price', 'status', 'compatible',
      'bullet1', 'bullet2', 'bullet3', 'bullet4', 'bullet5', 'bullet6', 'bullet7',
      'pro_width', 'pro_length', 'pro_height', 'pro_weight', 'meta_tag', 'meta_description', 'slug'
    ];

    const headers = rows[0];
    if (JSON.stringify(headers) !== JSON.stringify(expectedHeaders)) {
      await fs.unlink(req.file.path);
      return res.status(400).json({ error: 'Invalid Excel header format' });
    }

    // Validate foreign keys
    const validCategoryIds = (await db.query('SELECT category_id FROM categories', { type: db.QueryTypes.SELECT })).map(row => row.id);
    const validBrandIds = (await db.query('SELECT brand_id FROM brands', { type: db.QueryTypes.SELECT })).map(row => row.id);

    // SQL query
    const sql = `
      INSERT INTO products (
        product_title, product_description, product_keywords, category_id, brand_id,
        product_image1, product_image2, product_image3, product_image4, product_video,
        product_price, discount_percentage, selling_price, date, status, compatible,
        bullet1, bullet2, bullet3, bullet4, bullet5, bullet6, bullet7,
        pro_width, pro_length, pro_height, pro_weight, meta_tag, meta_description, slug
      ) VALUES (:product_title, :product_description, :product_keywords, :category_id, :brand_id,
        :product_image1, :product_image2, :product_image3, :product_image4, :product_video,
        :product_price, :discount_percentage, :selling_price, :date, :status, :compatible,
        :bullet1, :bullet2, :bullet3, :bullet4, :bullet5, :bullet6, :bullet7,
        :pro_width, :pro_length, :pro_height, :pro_weight, :meta_tag, :meta_description, :slug)
    `;

    // Process rows (skip header)
    let insertedCount = 0;
    for (const row of rows.slice(1)) {
      const values = row.map(value => (value === '' || value === undefined ? null : value));
      if (!values[0] || !values[3] || !values[4]) {
        console.warn(`Skipping row with missing required fields: ${values[0]}`);
        continue;
      }
      // if (!validCategoryIds.includes(Number(values[3]))) {
      //   console.warn(`Invalid category_id: ${values[3]}`);
      //   continue;
      // }
      // if (!validBrandIds.includes(Number(values[4]))) {
      //   console.warn(`Invalid brand_id: ${values[4]}`);
      //   continue;
      // }

      // Map values to named parameters
      const params = {
        product_title: values[0],
        product_description: values[1],
        product_keywords: values[2],
        category_id: Number(values[3]),
        brand_id: Number(values[4]),
        product_image1: values[5] || null,
        product_image2: values[6] || null,
        product_image3: values[7] || null,
        product_image4: values[8] || null,
        product_video: values[9] || null,
        product_price: Number(values[10]),
        discount_percentage: Number(values[11]),
        selling_price: Number(values[12]),
        date: new Date().toISOString().split('T')[0], // Use current date if not provided
        status: values[13] || 'active',
        compatible: values[14] || null,
        bullet1: values[15] || null,
        bullet2: values[16] || null,
        bullet3: values[17] || null,
        bullet4: values[18] || null,
        bullet5: values[19] || null,
        bullet6: values[20] || null,
        bullet7: values[21] || null,
        pro_width: Number(values[22]),
        pro_length: Number(values[23]),
        pro_height: Number(values[24]),
        pro_weight: Number(values[25]),
        meta_tag: values[26] || null,
        meta_description: values[27] || null,
        slug: values[28] || null
      };

      console.log('Inserting values:', params, 'Date:', params.date); // Debug: Log values

      await db.query(sql, {
        replacements: params,
        type: db.QueryTypes.INSERT
      });

      insertedCount++;
    }

    await fs.unlink(req.file.path);
    res.status(201).json({ message: `Successfully uploaded ${insertedCount} products` });
  } catch (err) {
    if (req.file && req.file.path) {
      await fs.unlink(req.file.path).catch(err => console.error('Error deleting file:', err));
    }
    handleError(res, err, 'Error uploading products from Excel');
  }
});



// --- Products APIs ---
app.get('/api/products', async (req, res) => {
  const { page = 1, limit = 10, category_id, brand_id, status, search } = req.query;
  const parsedLimit = parseInt(limit);
  const offset = (page - 1) * parsedLimit;
  let query = 'SELECT * FROM products WHERE 1=1';
  let countQuery = 'SELECT COUNT(*) as total FROM products WHERE 1=1';
  let params = [];
  let countParams = [];
  if (category_id) {
    query += ` AND category_id = "${category_id}"`;
    countQuery += ` AND category_id = "${category_id}"`;
    params.push(category_id);
    countParams.push(category_id);
  }
  if (brand_id) {
    query += ` AND brand_id = "${brand_id}"`;
    countQuery += ` AND brand_id = "${brand_id}"`;
    params.push(brand_id);
    countParams.push(brand_id);
  }
  if (status) {
    query += ' AND status = ?';
    countQuery += ' AND status = ?';
    params.push(status);
    countParams.push(status);
  }
  if (search) {
    query += ` AND (product_title LIKE "${search}" OR product_keywords LIKE "${search}")`;
    countQuery += ` AND (product_title LIKE "${search}" OR product_keywords LIKE "${search}")`;
    const searchTerm = `%${search}%`;
    params.push(searchTerm, searchTerm);
    countParams.push(searchTerm, searchTerm);
  }

  query += ` LIMIT ${parsedLimit} OFFSET ${offset}`;

  try {
    const [results] = await db.query(query, params);
    const [[{ total }]] = await db.query(countQuery, countParams);
    res.set('X-Total-Count', total);
    res.json(results);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error fetching products' });
  }
});

app.post('/api/productsforcart', async (req, res) => {
  try {
    const { ids } = req.body;

    // Validate input
    if (!Array.isArray(ids) || ids.length === 0) {
      return res.status(400).json({ error: 'Invalid or empty ID array' });
    }

    // Filter out NULL or invalid values
    const validIds = ids.filter(id => id !== null && id !== undefined && !isNaN(id));
    if (validIds.length === 0) {
      return res.status(400).json({ error: 'No valid IDs provided' });
    }

    const products = await db.query(
      `
      SELECT
        p.product_id AS id,
        p.product_title,
        p.product_price,
        p.discount_percentage,
        p.selling_price,
        p.product_image1,
        p.product_image2,
        p.product_image3,
        p.product_image4
      FROM products p
      WHERE p.product_id IN (:ids)
      `,
      {
        replacements: { ids: validIds },
        type: db.QueryTypes.SELECT,
      }
    );

    if (products.length === 0) {
      return res.status(404).json({ error: 'No products found' });
    }

    res.json(products);
  } catch (error) {
    console.error('Error fetching products:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/products/:slug', async (req, res) => {
  const { slug } = req.params;

  try {
    const [results] = await db.query(
      `SELECT * FROM products WHERE slug = '${slug}'`,
    );

    if (results.length === 0) {
      return res.status(404).json({ error: 'Product not found' });
    }

    res.json(results[0]);
  } catch (err) {
    console.error('SQL ERROR:', err); // 👈 log the actual MySQL error
    res.status(500).json({ error: 'Error fetching product', details: err.message });
  }
});



app.post('/api/products', upload.fields([
  { name: 'product_image1', maxCount: 1 },
  { name: 'product_image2', maxCount: 1 },
  { name: 'product_image3', maxCount: 1 },
  { name: 'product_image4', maxCount: 1 },
  { name: 'product_video', maxCount: 1 },
]), async (req, res) => {
  const {
    product_title, product_description, product_keywords, category_id, brand_id,
    product_price, discount_percentage, selling_price, status, compatible,
    bullet1, bullet2, bullet3, bullet4, bullet5, bullet6, bullet7,
    pro_width, pro_length, pro_height, pro_weight, meta_tag, meta_description, slug
  } = req.body;

  const product_image1 = req.files['product_image1'] ? `/uploads/images/${req.files['product_image1'][0].filename}` : '';
  const product_image2 = req.files['product_image2'] ? `/uploads/images/${req.files['product_image2'][0].filename}` : '';
  const product_image3 = req.files['product_image3'] ? `/uploads/images/${req.files['product_image3'][0].filename}` : '';
  const product_image4 = req.files['product_image4'] ? `/uploads/images/${req.files['product_image4'][0].filename}` : '';
  const product_video = req.files['product_video'] ? `/uploads/videos/${req.files['product_video'][0].filename}` : '';

  try {
    await db.query(
      `INSERT INTO products (
        product_title, product_description, product_keywords, category_id, brand_id,
        product_image1, product_image2, product_image3, product_image4, product_video,
        product_price, discount_percentage, selling_price, status, compatible,
        bullet1, bullet2, bullet3, bullet4, bullet5, bullet6, bullet7,
        pro_width, pro_length, pro_height, pro_weight, meta_tag, meta_description, slug
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        product_title, product_description, product_keywords, category_id, brand_id,
        product_image1, product_image2, product_image3, product_image4, product_video,
        product_price, discount_percentage, selling_price, status, compatible,
        bullet1, bullet2, bullet3, bullet4, bullet5, bullet6, bullet7,
        pro_width, pro_length, pro_height, pro_weight, meta_tag, meta_description, slug
      ]
    );
    res.status(201).json({ message: 'Product created' });
  } catch (err) {
    handleError(res, err, 'Error creating product');
  }
});

app.put('/api/products/:id', upload.fields([
  { name: 'product_image1', maxCount: 1 },
  { name: 'product_image2', maxCount: 1 },
  { name: 'product_image3', maxCount: 1 },
  { name: 'product_image4', maxCount: 1 },
  { name: 'product_video', maxCount: 1 },
]), async (req, res) => {
  const { id } = req.params;
  const {
    product_title, product_description, product_keywords, category_id, brand_id,
    product_price, discount_percentage, selling_price, status, compatible,
    bullet1, bullet2, bullet3, bullet4, bullet5, bullet6, bullet7,
    pro_width, pro_length, pro_height, pro_weight, meta_tag, meta_description, slug
  } = req.body;

  const product_image1 = req.files['product_image1'] ? `/uploads/images/${req.files['product_image1'][0].filename}` : null;
  const product_image2 = req.files['product_image2'] ? `/uploads/images/${req.files['product_image2'][0].filename}` : null;
  const product_image3 = req.files['product_image3'] ? `/uploads/images/${req.files['product_image3'][0].filename}` : null;
  const product_image4 = req.files['product_image4'] ? `/uploads/images/${req.files['product_image4'][0].filename}` : null;
  const product_video = req.files['product_video'] ? `/uploads/videos/${req.files['product_video'][0].filename}` : null;

  try {
    await db.query(
      `UPDATE products SET
        product_title = ?, product_description = ?, product_keywords = ?, category_id = ?, brand_id = ?,
        product_image1 = COALESCE(?, product_image1), product_image2 = COALESCE(?, product_image2),
        product_image3 = COALESCE(?, product_image3), product_image4 = COALESCE(?, product_image4),
        product_video = COALESCE(?, product_video), product_price = ?, discount_percentage = ?,
        selling_price = ?, status = ?, compatible = ?, bullet1 = ?, bullet2 = ?, bullet3 = ?,
        bullet4 = ?, bullet5 = ?, bullet6 = ?, bullet7 = ?, pro_width = ?, pro_length = ?,
        pro_height = ?, pro_weight = ?, meta_tag = ?, meta_description = ?, slug = ?
        WHERE product_id = ?`,
      [
        product_title, product_description, product_keywords, category_id, brand_id,
        product_image1, product_image2, product_image3, product_image4, product_video,
        product_price, discount_percentage, selling_price, status, compatible,
        bullet1, bullet2, bullet3, bullet4, bullet5, bullet6, bullet7,
        pro_width, pro_length, pro_height, pro_weight, meta_tag, meta_description, slug, id
      ]
    );
    res.json({ message: 'Product updated' });
  } catch (err) {
    handleError(res, err, 'Error updating product');
  }
});

app.delete('/api/products/:id', async (req, res) => {
  const { id } = req.params;
  try {
    await db.query('DELETE FROM products WHERE product_id = :id', {
      replacements: { id },
      type: db.QueryTypes.DELETE
    });
    res.json({ message: 'Product deleted' });
  } catch (err) {
    handleError(res, err, 'Error deleting product');
  }
});

// --- Cart Details APIs ---
app.get('/api/cart', async (req, res) => {
  try {
    const [results] = await db.query('SELECT * FROM cart_details');
    res.json(results);
  } catch (err) {
    handleError(res, err, 'Error fetching cart details');
  }
});


app.get('/api/cart/:user_id', async (req, res) => {
  const { user_id } = req.params;

  // Validate input
  // const parsedUserId = parseInt(user_id, 10);
  // if (isNaN(parsedUserId)) {
  //   return res.status(400).json({ error: 'Invalid user_id: must be a valid number' });
  // }

  try {
    const results = await db.query(
      `
      SELECT 
        cd.product_id,
        cd.quantity,
        cd.user_id,
        cd.id,
        p.product_title,
        p.product_price,
        p.discount_percentage,
        p.selling_price,
        p.product_image1,
        p.product_image2,
        p.product_image3,
        p.product_image4
      FROM cart_details cd
      INNER JOIN products p ON cd.product_id = p.product_id
      WHERE cd.user_id = :user_id
      `,
      {
        replacements: { user_id: user_id },
        type: db.QueryTypes.SELECT,
      }
    );

    if (results.length === 0) {
      return res.status(404).json({ message: 'No items found in cart for this user' });
    }

    res.status(200).json(results);
  } catch (err) {
    console.error('Database error:', err);
    return res.status(500).json({ error: 'Error fetching cart details', details: err.message });
  }
});

app.post('/api/cart', async (req, res) => {
  const { product_id, quantity, user_id } = req.body;

  // Validate input
  if (!product_id || !quantity || !user_id || quantity < 1) {
    return res.status(400).json({ error: 'Invalid input: product_id, quantity, and user_id are required, and quantity must be positive' });
  }

  // Ensure inputs are of correct type (convert to integers if necessary)
  const parsedProductId = parseInt(product_id, 10);
  const parsedQuantity = parseInt(quantity, 10);
  // const parsedUserId = parseInt(user_id, 10);

  if (isNaN(parsedProductId) || isNaN(parsedQuantity)) {
    return res.status(400).json({ error: 'Invalid input: product_id, quantity, and user_id must be valid numbers' });
  }

  const transaction = await db.transaction();
  try {
    // Check if cart item exists
    const [existingItem] = await db.query(
      'SELECT * FROM cart_details WHERE user_id = :user_id AND product_id = :product_id',
      {
        replacements: { user_id: user_id, product_id: parsedProductId },
        type: db.QueryTypes.SELECT,
        transaction,
      }
    );

    if (existingItem) {
      // Item exists, update quantity
      const newQuantity = existingItem.quantity + parsedQuantity;
      await db.query(
        'UPDATE cart_details SET quantity = :quantity WHERE user_id = :user_id AND product_id = :product_id',
        {
          replacements: { quantity: newQuantity, user_id: user_id, product_id: parsedProductId },
          type: db.QueryTypes.UPDATE,
          transaction,
        }
      );
      await transaction.commit();
      return res.status(200).json({ message: 'Cart item quantity updated', quantity: newQuantity });
    } else {
      // Item doesn't exist, insert new cart item
      await db.query(
        'INSERT INTO cart_details (product_id, quantity, user_id) VALUES (:product_id, :quantity, :user_id)',
        {
          replacements: { product_id: parsedProductId, quantity: parsedQuantity, user_id: user_id },
          type: db.QueryTypes.INSERT,
          transaction,
        }
      );
      await transaction.commit();
      return res.status(201).json({ message: 'Cart item added' });
    }
  } catch (err) {
    await transaction.rollback();
    console.error('Database error:', err);
    return res.status(500).json({ error: 'Error processing cart item', details: err.message });
  }
});
app.put('/api/cart/:id', async (req, res) => {
  const { id } = req.params;
  const { product_id, ip_address, quantity, user_id } = req.body;
  try {
    await db.query(
      'UPDATE cart_details SET product_id = ?, ip_address = ?, quantity = ?, user_id = ? WHERE id = ?',
      [product_id, ip_address, quantity, user_id, id]
    );
    res.json({ message: 'Cart item updated' });
  } catch (err) {
    handleError(res, err, 'Error updating cart item');
  }
});

app.delete('/api/cart/:id', async (req, res) => {
  const { id } = req.params;
  try {
    await db.query(`DELETE FROM cart_details WHERE id = ${id}`);
    res.json({ message: 'Cart item deleted' });
  } catch (err) {
    handleError(res, err, 'Error deleting cart item');
  }
});

// --- Wishlist Details APIs ---
app.get('/api/wishlist', async (req, res) => {
  try {
    const [results] = await db.query('SELECT * FROM whishlist_details');
    res.json(results);
  } catch (err) {
    handleError(res, err, 'Error fetching wishlist details');
  }
});

app.get('/api/wishlist/:user_id', async (req, res) => {
  const { user_id } = req.params;
  try {
    const [results] = await db.query(`SELECT * FROM whishlist_details WHERE user_id=${user_id}`);
    res.json(results);
  } catch (err) {
    handleError(res, err, 'Error fetching wishlist details');
  }
});

app.post('/api/wishlist', async (req, res) => {
  const { product_id, ip_address, quantity, user_id } = req.body;
  try {
    await db.query(
      'INSERT INTO whishlist_details (product_id, ip_address, quantity, user_id) VALUES (?, ?, ?, ?)',
      [product_id, ip_address, quantity, user_id]
    );
    res.status(201).json({ message: 'Wishlist item added' });
  } catch (err) {
    handleError(res, err, 'Error adding wishlist item');
  }
});

app.put('/api/wishlist/:id', async (req, res) => {
  const { id } = req.params;
  const { product_id, ip_address, quantity, user_id } = req.body;
  try {
    await db.query(
      'UPDATE whishlist_details SET product_id = ?, ip_address = ?, quantity = ?, user_id = ? WHERE id = ?',
      [product_id, ip_address, quantity, user_id, id]
    );
    res.json({ message: 'Wishlist item updated' });
  } catch (err) {
    handleError(res, err, 'Error updating wishlist item');
  }
});

app.delete('/api/wishlist/:id', async (req, res) => {
  const { id } = req.params;
  try {
    await db.query('DELETE FROM whishlist_details WHERE id = ?', [id]);
    res.json({ message: 'Wishlist item deleted' });
  } catch (err) {
    handleError(res, err, 'Error deleting wishlist item');
  }
});

// --- User Orders APIs ---
app.get('/api/orders', async (req, res) => {
  try {
    const [results] = await db.query('SELECT * FROM user_orders');
    res.json(results);
  } catch (err) {
    handleError(res, err, 'Error fetching orders');
  }
});

app.get('/api/user/orders', authenticateToken,async (req, res) => {
  try {
    const [results] = await db.query(`SELECT * FROM user_orders WHERE user_id = ${req.userId}`);
    res.json(results);
  } catch (err) {
    handleError(res, err, 'Error fetching orders');
  }
});

app.post('/api/orders', async (req, res) => {
  const {
    user_id, amount_due, invoice_number, total_products, shipping_id, order_status, status,
    est_delivery, delivery_date, tracking_link, shipment_id, shiprocket_order_id,
    return_order_no, return_shipment_id, return_shiprocket_order_no, return_cancel_count,
    is_shipped, is_picked_up, is_cancel_approved, is_return_approved, cancel_attampted,
    return_attampted, is_refund
  } = req.body;
  try {
    await db.query(
      `INSERT INTO user_orders (
        user_id, amount_due, invoice_number, total_products, shipping_id, order_status, status,
        est_delivery, delivery_date, tracking_link, shipment_id, shiprocket_order_id,
        return_order_no, return_shipment_id, return_shiprocket_order_no, return_cancel_count,
        is_shipped, is_picked_up, is_cancel_approved, is_return_approved, cancel_attampted,
        return_attampted, is_refund
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        user_id, amount_due, invoice_number, total_products, shipping_id, order_status, status,
        est_delivery, delivery_date, tracking_link, shipment_id, shiprocket_order_id,
        return_order_no, return_shipment_id, return_shiprocket_order_no, return_cancel_count,
        is_shipped, is_picked_up, is_cancel_approved, is_return_approved, cancel_attampted,
        return_attampted, is_refund
      ]
    );
    res.status(201).json({ message: 'Order created' });
  } catch (err) {
    handleError(res, err, 'Error creating order');
  }
});

app.put('/api/orders/:id', async (req, res) => {
  const { id } = req.params;
  const {
    user_id, amount_due, invoice_number, total_products, shipping_id, order_status, status,
    est_delivery, delivery_date, tracking_link, shipment_id, shiprocket_order_id,
    return_order_no, return_shipment_id, return_shiprocket_order_no, return_cancel_count,
    is_shipped, is_picked_up, is_cancel_approved, is_return_approved, cancel_attampted,
    return_attampted, is_refund
  } = req.body;
  try {
    await db.query(
      `UPDATE user_orders SET
        user_id = ?, amount_due = ?, invoice_number = ?, total_products = ?, shipping_id = ?,
        order_status = ?, status = ?, est_delivery = ?, delivery_date = ?, tracking_link = ?,
        shipment_id = ?, shiprocket_order_id = ?, return_order_no = ?, return_shipment_id = ?,
        return_shiprocket_order_no = ?, return_cancel_count = ?, is_shipped = ?,
        is_picked_up = ?, is_cancel_approved = ?, is_return_approved = ?, cancel_attampted = ?,
        return_attampted = ?, is_refund = ?
        WHERE order_id = ?`,
      [
        user_id, amount_due, invoice_number, total_products, shipping_id, order_status, status,
        est_delivery, delivery_date, tracking_link, shipment_id, shiprocket_order_id,
        return_order_no, return_shipment_id, return_shiprocket_order_no, return_cancel_count,
        is_shipped, is_picked_up, is_cancel_approved, is_return_approved, cancel_attampted,
        return_attampted, is_refund, id
      ]
    );
    res.json({ message: 'Order updated' });
  } catch (err) {
    handleError(res, err, 'Error updating order');
  }
});

app.delete('/api/orders/:id', async (req, res) => {
  const { id } = req.params;
  try {
    await db.query('DELETE FROM user_orders WHERE order_id = ?', [id]);
    res.json({ message: 'Order deleted' });
  } catch (err) {
    handleError(res, err, 'Error deleting order');
  }
});

// --- Order Details APIs ---
app.get('/api/order-details', async (req, res) => {
  try {
    const [results] = await db.query('SELECT * FROM order_details');
    res.json(results);
  } catch (err) {
    handleError(res, err, 'Error fetching order details');
  }
});

app.post('/api/order-details', async (req, res) => {
  const { order_id, product_id, quantity, cost_price, discount, discount_percentage, selling_price } = req.body;
  try {
    await db.query(
      'INSERT INTO order_details (order_id, product_id, quantity, cost_price, discount, discount_percentage, selling_price) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [order_id, product_id, quantity, cost_price, discount, discount_percentage, selling_price]
    );
    res.status(201).json({ message: 'Order detail added' });
  } catch (err) {
    handleError(res, err, 'Error adding order detail');
  }
});

app.put('/api/order-details/:id', async (req, res) => {
  const { id } = req.params;
  const { order_id, product_id, quantity, cost_price, discount, discount_percentage, selling_price } = req.body;
  try {
    await db.query(
      'UPDATE order_details SET order_id = ?, product_id = ?, quantity = ?, cost_price = ?, discount = ?, discount_percentage = ?, selling_price = ? WHERE id = ?',
      [order_id, product_id, quantity, cost_price, discount, discount_percentage, selling_price, id]
    );
    res.json({ message: 'Order detail updated' });
  } catch (err) {
    handleError(res, err, 'Error updating order detail');
  }
});

app.delete('/api/order-details/:id', async (req, res) => {
  const { id } = req.params;
  try {
    await db.query('DELETE FROM order_details WHERE id = ?', [id]);
    res.json({ message: 'Order detail deleted' });
  } catch (err) {
    handleError(res, err, 'Error deleting order detail');
  }
});

// --- Ordered Product Details APIs ---
app.get('/api/ordered-product-details', async (req, res) => {
  try {
    const [results] = await db.query('SELECT * FROM ordered_product_details');
    res.json(results);
  } catch (err) {
    handleError(res, err, 'Error fetching ordered product details');
  }
});

app.post('/api/ordered-product-details', async (req, res) => {
  const { order_id, user_id, product_id, cost_price, discount, selling_price, discount_percentage } = req.body;
  try {
    await db.query(
      'INSERT INTO ordered_product_details (order_id, user_id, product_id, cost_price, discount, selling_price, discount_percentage) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [order_id, user_id, product_id, cost_price, discount, selling_price, discount_percentage]
    );
    res.status(201).json({ message: 'Ordered product detail added' });
  } catch (err) {
    handleError(res, err, 'Error adding ordered product detail');
  }
});

app.put('/api/ordered-product-details/:id', async (req, res) => {
  const { id } = req.params;
  const { order_id, user_id, product_id, cost_price, discount, selling_price, discount_percentage } = req.body;
  try {
    await db.query(
      'UPDATE ordered_product_details SET order_id = ?, user_id = ?, product_id = ?, cost_price = ?, discount = ?, selling_price = ?, discount_percentage = ? WHERE id = ?',
      [order_id, user_id, product_id, cost_price, discount, selling_price, discount_percentage, id]
    );
    res.json({ message: 'Ordered product detail updated' });
  } catch (err) {
    handleError(res, err, 'Error updating ordered product detail');
  }
});

app.delete('/api/ordered-product-details/:id', async (req, res) => {
  const { id } = req.params;
  try {
    await db.query('DELETE FROM ordered_product_details WHERE id = ?', [id]);
    res.json({ message: 'Ordered product detail deleted' });
  } catch (err) {
    handleError(res, err, 'Error deleting ordered product detail');
  }
});

// --- Orders Pending APIs ---
app.get('/api/orders-pending', async (req, res) => {
  try {
    const [results] = await db.query('SELECT * FROM orders_pending');
    res.json(results);
  } catch (err) {
    handleError(res, err, 'Error fetching pending orders');
  }
});

app.post('/api/orders-pending', async (req, res) => {
  const { user_id, invoice_number, product_id, quantity, order_status } = req.body;
  try {
    await db.query(
      'INSERT INTO orders_pending (user_id, invoice_number, product_id, quantity, order_status) VALUES (?, ?, ?, ?, ?)',
      [user_id, invoice_number, product_id, quantity, order_status]
    );
    res.status(201).json({ message: 'Pending order added' });
  } catch (err) {
    handleError(res, err, 'Error adding pending order');
  }
});

app.put('/api/orders-pending/:id', async (req, res) => {
  const { id } = req.params;
  const { user_id, invoice_number, product_id, quantity, order_status } = req.body;
  try {
    await db.query(
      'UPDATE orders_pending SET user_id = ?, invoice_number = ?, product_id = ?, quantity = ?, order_status = ? WHERE order_id = ?',
      [user_id, invoice_number, product_id, quantity, order_status, id]
    );
    res.json({ message: 'Pending order updated' });
  } catch (err) {
    handleError(res, err, 'Error updating pending order');
  }
});

app.delete('/api/orders-pending/:id', async (req, res) => {
  const { id } = req.params;
  try {
    await db.query('DELETE FROM orders_pending WHERE order_id = ?', [id]);
    res.json({ message: 'Pending order deleted' });
  } catch (err) {
    handleError(res, err, 'Error deleting pending order');
  }
});

// --- User Payments APIs ---
app.get('/api/payments', async (req, res) => {
  try {
    const [results] = await db.query('SELECT * FROM user_payments');
    res.json(results);
  } catch (err) {
    handleError(res, err, 'Error fetching payments');
  }
});

app.post('/api/payments', async (req, res) => {
  const { order_id, payment_id, user_id, amount, cost_price, discount, gst, delivery_fee, payment_mode } = req.body;
  try {
    await db.query(
      'INSERT INTO user_payments (order_id, payment_id, user_id, amount, cost_price, discount, gst, delivery_fee, payment_mode) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
      [order_id, payment_id, user_id, amount, cost_price, discount, gst, delivery_fee, payment_mode]
    );
    res.status(201).json({ message: 'Payment added' });
  } catch (err) {
    handleError(res, err, 'Error adding payment');
  }
});

app.put('/api/payments/:id', async (req, res) => {
  const { id } = req.params;
  const { order_id, payment_id, user_id, amount, cost_price, discount, gst, delivery_fee, payment_mode } = req.body;
  try {
    await db.query(
      'UPDATE user_payments SET order_id = ?, payment_id = ?, user_id = ?, amount = ?, cost_price = ?, discount = ?, gst = ?, delivery_fee = ?, payment_mode = ? WHERE id = ?',
      [order_id, payment_id, user_id, amount, cost_price, discount, gst, delivery_fee, payment_mode, id]
    );
    res.json({ message: 'Payment updated' });
  } catch (err) {
    handleError(res, err, 'Error updating payment');
  }
});

app.delete('/api/payments/:id', async (req, res) => {
  const { id } = req.params;
  try {
    await db.query('DELETE FROM user_payments WHERE id = ?', [id]);
    res.json({ message: 'Payment deleted' });
  } catch (err) {
    handleError(res, err, 'Error deleting payment');
  }
});

// --- Reviews APIs ---
app.get('/api/reviews', async (req, res) => {
  try {
    const [results] = await db.query('SELECT * FROM reviews');
    res.json(results);
  } catch (err) {
    handleError(res, err, 'Error fetching reviews');
  }
});

app.post('/api/reviews', async (req, res) => {
  const { user_id, rating, product_id } = req.body;
  try {
    await db.query(
      'INSERT INTO reviews (user_id, rating, product_id) VALUES (?, ?, ?)',
      [user_id, rating, product_id]
    );
    res.status(201).json({ message: 'Review added' });
  } catch (err) {
    handleError(res, err, 'Error adding review');
  }
});

app.put('/api/reviews/:id', async (req, res) => {
  const { id } = req.params;
  const { user_id, rating, product_id } = req.body;
  try {
    await db.query(
      'UPDATE reviews SET user_id = ?, rating = ?, product_id = ? WHERE id = ?',
      [user_id, rating, product_id, id]
    );
    res.json({ message: 'Review updated' });
  } catch (err) {
    handleError(res, err, 'Error updating review');
  }
});

app.delete('/api/reviews/:id', async (req, res) => {
  const { id } = req.params;
  try {
    await db.query('DELETE FROM reviews WHERE id = ?', [id]);
    res.json({ message: 'Review deleted' });
  } catch (err) {
    handleError(res, err, 'Error deleting review');
  }
});

// --- Comments APIs ---
app.get('/api/comments', async (req, res) => {
  try {
    const [results] = await db.query('SELECT * FROM comments');
    res.json(results);
  } catch (err) {
    handleError(res, err, 'Error fetching comments');
  }
});

app.post('/api/comments', async (req, res) => {
  const { user_id, product_id, comments } = req.body;
  try {
    await db.query(
      'INSERT INTO comments (user_id, product_id, comments) VALUES (?, ?, ?)',
      [user_id, product_id, comments]
    );
    res.status(201).json({ message: 'Comment added' });
  } catch (err) {
    handleError(res, err, 'Error adding comment');
  }
});

app.put('/api/comments/:id', async (req, res) => {
  const { id } = req.params;
  const { user_id, product_id, comments } = req.body;
  try {
    await db.query(
      'UPDATE comments SET user_id = ?, product_id = ?, comments = ? WHERE serial_num = ?',
      [user_id, product_id, comments, id]
    );
    res.json({ message: 'Comment updated' });
  } catch (err) {
    handleError(res, err, 'Error updating comment');
  }
});

app.delete('/api/comments/:id', async (req, res) => {
  const { id } = req.params;
  try {
    await db.query('DELETE FROM comments WHERE serial_num = ?', [id]);
    res.json({ message: 'Comment deleted' });
  } catch (err) {
    handleError(res, err, 'Error deleting comment');
  }
});

// --- Cancel/Return Reasons APIs ---
app.get('/api/cancel-return-reasons', async (req, res) => {
  try {
    const [results] = await db.query('SELECT * FROM cancel_return_reasons');
    res.json(results);
  } catch (err) {
    handleError(res, err, 'Error fetching cancel/return reasons');
  }
});

app.post('/api/cancel-return-reasons', async (req, res) => {
  const { order_id, reason, cancel_or_return, comment } = req.body;
  try {
    await db.query(
      'INSERT INTO cancel_return_reasons (order_id, reason, cancel_or_return, comment) VALUES (?, ?, ?, ?)',
      [order_id, reason, cancel_or_return, comment]
    );
    res.status(201).json({ message: 'Cancel/return reason added' });
  } catch (err) {
    handleError(res, err, 'Error adding cancel/return reason');
  }
});

app.put('/api/cancel-return-reasons/:id', async (req, res) => {
  const { id } = req.params;
  const { order_id, reason, cancel_or_return, comment } = req.body;
  try {
    await db.query(
      'UPDATE cancel_return_reasons SET order_id = ?, reason = ?, cancel_or_return = ?, comment = ? WHERE id = ?',
      [order_id, reason, cancel_or_return, comment, id]
    );
    res.json({ message: 'Cancel/return reason updated' });
  } catch (err) {
    handleError(res, err, 'Error updating cancel/return reason');
  }
});

app.delete('/api/cancel-return-reasons/:id', async (req, res) => {
  const { id } = req.params;
  try {
    await db.query('DELETE FROM cancel_return_reasons WHERE id = ?', [id]);
    res.json({ message: 'Cancel/return reason deleted' });
  } catch (err) {
    handleError(res, err, 'Error deleting cancel/return reason');
  }
});

// --- Cancel/Return Refunds APIs ---
app.get('/api/cancel-return-refunds', async (req, res) => {
  try {
    const [results] = await db.query('SELECT * FROM cancel_return_refunds');
    res.json(results);
  } catch (err) {
    handleError(res, err, 'Error fetching cancel/return refunds');
  }
});

app.post('/api/cancel-return-refunds', async (req, res) => {
  const { order_id, refund_id, refund_amt } = req.body;
  try {
    await db.query(
      'INSERT INTO cancel_return_refunds (order_id, refund_id, refund_amt) VALUES (?, ?, ?)',
      [order_id, refund_id, refund_amt]
    );
    res.status(201).json({ message: 'Refund added' });
  } catch (err) {
    handleError(res, err, 'Error adding refund');
  }
});

app.put('/api/cancel-return-refunds/:id', async (req, res) => {
  const { id } = req.params;
  const { order_id, refund_id, refund_amt } = req.body;
  try {
    await db.query(
      'UPDATE cancel_return_refunds SET order_id = ?, refund_id = ?, refund_amt = ? WHERE id = ?',
      [order_id, refund_id, refund_amt, id]
    );
    res.json({ message: 'Refund updated' });
  } catch (err) {
    handleError(res, err, 'Error updating refund');
  }
});

app.delete('/api/cancel-return-refunds/:id', async (req, res) => {
  const { id } = req.params;
  try {
    await db.query('DELETE FROM cancel_return_refunds WHERE id = ?', [id]);
    res.json({ message: 'Refund deleted' });
  } catch (err) {
    handleError(res, err, 'Error deleting refund');
  }
});

// --- Warranty APIs ---
app.get('/api/warranty', async (req, res) => {
  try {
    const [results] = await db.query('SELECT * FROM warranty');
    res.json(results);
  } catch (err) {
    handleError(res, err, 'Error fetching warranty records');
  }
});

app.post('/api/warranty', upload.single('invoice_img'), async (req, res) => {
  const { user_id, user_username, user_email, user_contact, purchase_place, date, model_num, ip_address } = req.body;
  const invoice_img = req.file ? `/uploads/documents/${req.file.filename}` : '';
  try {
    await db.query(
      'INSERT INTO warranty (user_id, user_username, user_email, user_contact, purchase_place, date, model_num, invoice_img, ip_address) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
      [user_id, user_username, user_email, user_contact, purchase_place, date, model_num, invoice_img, ip_address]
    );
    res.status(201).json({ message: 'Warranty record added' });
  } catch (err) {
    handleError(res, err, 'Error adding warranty record');
  }
});

// Get all payments for a user
app.get('/api/users/payments', async (req, res) => {
  try {
    const payments = await db.query('SELECT * FROM user_payments join user_table on user_payments.user_id = user_table.user_id join order_details on user_payments.order_id = order_details.order_id join products on order_details.product_id = products.product_id');
    res.json(payments);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/warranty/:id', upload.single('invoice_img'), async (req, res) => {
  const { id } = req.params;
  const { user_id, user_username, user_email, user_contact, purchase_place, date, model_num, ip_address } = req.body;
  const invoice_img = req.file ? `/uploads/documents/${req.file.filename}` : null;
  try {
    await db.query(
      'UPDATE warranty SET user_id = ?, user_username = ?, user_email = ?, user_contact = ?, purchase_place = ?, date = ?, model_num = ?, invoice_img = COALESCE(?, invoice_img), ip_address = ? WHERE user_id = ?',
      [user_id, user_username, user_email, user_contact, purchase_place, date, model_num, invoice_img, ip_address, id]
    );
    res.json({ message: 'Warranty record updated' });
  } catch (err) {
    handleError(res, err, 'Error updating warranty record');
  }
});

app.delete('/api/warranty/:id', async (req, res) => {
  const { id } = req.params;
  console.log(`Deleting warranty with user_id: ${id}`);
  try {
    const result = await db.query(
      'DELETE FROM warranty WHERE user_id = :id',
      {
        replacements: { id },
        type: db.QueryTypes.DELETE
      }
    );

    res.json({ message: 'Warranty record deleted successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error deleting warranty record' });
  }
});


// --- Warranty Claims APIs ---
app.get('/api/warranty-claims', async (req, res) => {
  try {
    const [results] = await db.query('SELECT * FROM warrantyclaim');
    res.json(results);
  } catch (err) {
    handleError(res, err, 'Error fetching warranty claims');
  }
});

app.post('/api/warranty-claims', upload.single('invoice_img'), async (req, res) => {
  const { username, email, contact, purchase_place, model_num, date, msg, current_status } = req.body;
  const invoice_img = req.file ? `/uploads/documents/${req.file.filename}` : '';
  try {
    await db.query(
      'INSERT INTO warrantyclaim (username, email, contact, purchase_place, model_num, date, msg, invoice_img, current_status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
      [username, email, contact, purchase_place, model_num, date, msg, invoice_img, current_status]
    );
    res.status(201).json({ message: 'Warranty claim added' });
  } catch (err) {
    handleError(res, err, 'Error adding warranty claim');
  }
});

app.put('/api/warranty-claims/:id', upload.single('invoice_img'), async (req, res) => {
  const { id } = req.params;
  const { username, email, contact, purchase_place, model_num, date, msg, current_status } = req.body;
  const invoice_img = req.file ? `/uploads/documents/${req.file.filename}` : null;
  try {
    await db.query(
      'UPDATE warrantyclaim SET username = ?, email = ?, contact = ?, purchase_place = ?, model_num = ?, date = ?, msg = ?, invoice_img = COALESCE(?, invoice_img), current_status = ? WHERE id = ?',
      [username, email, contact, purchase_place, model_num, date, msg, invoice_img, current_status, id]
    );
    res.json({ message: 'Warranty claim updated' });
  } catch (err) {
    handleError(res, err, 'Error updating warranty claim');
  }
});

app.delete('/api/warranty-claims/:id', async (req, res) => {
  const { id } = req.params;
  if (!id || isNaN(id)) {
    return res.status(400).json({ error: 'Invalid ID parameter' });
  }

  try {
    const result = await db.query(
      'DELETE FROM warrantyclaim WHERE id = :id',
      {
        replacements: { id },
        type: db.QueryTypes.DELETE
      }
    );

    res.json({ message: 'Warranty claim deleted successfully' });
  } catch (err) {
    console.error('Error deleting warranty claim:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});



// --- Cron Test APIs ---
app.get('/api/cron-test', async (req, res) => {
  try {
    const [results] = await db.query('SELECT * FROM cron_test');
    res.json(results);
  } catch (err) {
    handleError(res, err, 'Error fetching cron test records');
  }
});

app.post('/api/cron-test', async (req, res) => {
  const { inserted } = req.body;
  try {
    await db.query(
      'INSERT INTO cron_test (inserted) VALUES (?)',
      [inserted]
    );
    res.status(201).json({ message: 'Cron test record added' });
  } catch (err) {
    handleError(res, err, 'Error adding cron test record');
  }
});

app.delete('/api/cron-test/:id', async (req, res) => {
  const { id } = req.params;
  try {
    await db.query('DELETE FROM cron_test WHERE id = ?', [id]);
    res.json({ message: 'Cron test record deleted' });
  } catch (err) {
    handleError(res, err, 'Error deleting cron test record');
  }
});

// --- User Table APIs ---
app.get('/api/users', async (req, res) => {
  try {
    const [results] = await db.query('SELECT user_id,username,user_email, user_image,user_ip,user_address,user_mobile FROM user_table');
    res.json(results);
  } catch (err) {
    handleError(res, err, 'Error fetching users');
  }
});

app.get('/api/myprofile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findOne({
      where: { user_id: req.userId }
    });

    if (!user) return res.status(404).json({ message: 'User not found' });

    res.json({ user });
  } catch (err) {
    console.error('Profile error:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});


app.post('/api/users', upload.single('user_image'), async (req, res) => {
  const {
    username,
    uid,
    user_email,
    user_password = null,
    user_address = null,
    user_mobile = null
  } = req.body;

  const user_image = req.file ? `/uploads/images/${req.file.filename}` : null;

  if (!uid || !user_email || !username) {
    return res.status(400).json({ error: 'Missing required fields: uid, user_email, username' });
  }

  const jwtSecret = process.env.JWT_SECRET;
  if (!jwtSecret) {
    console.error('JWT_SECRET is not defined in environment variables');
    return res.status(500).json({ error: 'Server configuration error: JWT_SECRET is missing' });
  }

  try {
    const existingUser = await db.query(
      `SELECT user_id, username, uid, user_email, user_image, user_address, user_mobile 
       FROM user_table 
       WHERE uid = :uid`,
      {
        replacements: { uid },
        type: db.QueryTypes.SELECT
      }
    );

    const tokenOptions = { expiresIn: '1h', algorithm: 'HS256' };

    if (existingUser.length > 0) {
      const user = existingUser[0];
      const payload = {
        id: user.user_id,
        uid: user.uid,
        user_email: user.user_email,
        username: user.username
      };
      const generatedToken = jwt.sign(payload, jwtSecret, tokenOptions);

      await db.query(
        `UPDATE user_table 
         SET token = :token, token_created = :token_created 
         WHERE uid = :uid`,
        {
          replacements: {
            token: generatedToken,
            token_created: new Date().toISOString(),
            uid
          },
          type: db.QueryTypes.UPDATE
        }
      );

      return res.status(200).json({
        message: 'User already exists, token regenerated',
        user: {
          id: user.user_id,
          username: user.username,
          uid: user.uid,
          user_email: user.user_email,
          user_image: user.user_image,
          user_address: user.user_address,
          user_mobile: user.user_mobile,
          token: generatedToken,
          token_created: new Date().toISOString()
        }
      });
    }

    // Build insert query for new user
    const fields = ['username', 'uid', 'user_email'];
    const values = { username, uid, user_email };

    if (user_password !== null) {
      fields.push('user_password');
      values.user_password = await bcrypt.hash(user_password, 10);
    }
    if (user_image !== null) {
      fields.push('user_image');
      values.user_image = user_image;
    }
    if (user_address !== null) {
      fields.push('user_address');
      values.user_address = user_address;
    }
    if (user_mobile !== null) {
      fields.push('user_mobile');
      values.user_mobile = user_mobile;
    }

    const placeholders = fields.map(field => `:${field}`).join(', ');
    const insertQuery = `INSERT INTO user_table (${fields.join(', ')}) VALUES (${placeholders}) RETURNING user_id`;
    const [inserted] = await db.query(insertQuery, {
      replacements: values,
      type: db.QueryTypes.INSERT
    });

    const insertedId = inserted.user_id;
    const payload = { id: insertedId, uid, user_email, username };
    const generatedToken = jwt.sign(payload, jwtSecret, tokenOptions);

    await db.query(
      `UPDATE user_table 
       SET token = :token, token_created = :token_created 
       WHERE user_id = :id`,
      {
        replacements: {
          token: generatedToken,
          token_created: new Date().toISOString(),
          id: insertedId
        },
        type: db.QueryTypes.UPDATE
      }
    );

    const [newUser] = await db.query(
      `SELECT user_id, username, uid, user_email, user_image, user_address, user_mobile, token, token_created 
       FROM user_table 
       WHERE user_id = :id`,
      {
        replacements: { id: insertedId },
        type: db.QueryTypes.SELECT
      }
    );

    return res.status(200).json({
      message: 'User added and token generated',
      user: newUser
    });
  } catch (err) {
    console.error('Error processing user:', err);
    res.status(500).json({ error: 'Error processing user', details: err.message });
  }
});



app.put('/api/users/:id', upload.single('user_image'), async (req, res) => {
  const { id } = req.params;
  const { username, user_email, user_password, user_address, user_mobile, token, token_created } = req.body;
  const user_image = req.file ? `/uploads/images/${req.file.filename}` : null;
  try {
    await db.query(
      'UPDATE user_table SET username = ?, user_email = ?, user_password = ?, user_image = COALESCE(?, user_image), user_address = ?, user_mobile = ?, token = ?, token_created = ? WHERE user_id = ?',
      [username, user_email, user_password, user_image, user_address, user_mobile, token, token_created, id]
    );
    res.json({ message: 'User updated' });
  } catch (err) {
    handleError(res, err, 'Error updating user');
  }
});

app.delete('/api/users/:id', async (req, res) => {
  const { id } = req.params;
  try {
    await db.query('DELETE FROM user_table WHERE user_id = :id',
     {
      replacements: { id },
      type: db.QueryTypes.DELETE
    });
    res.json({ message: 'User deleted' });
  } catch (err) {
    handleError(res, err, 'Error deleting user');
  }
});

app.post('/status/:txnId', async (req, res) => {
  try {
    const merchantTransactionId = req.params.txnId;
    const merchantId = process.env.PHONEPE_MERCHANT_ID;
    const keyIndex = process.env.PHONEPE_SALT_INDEX || 1;
    const string = `/pg/v1/status/${merchantId}/${merchantTransactionId}` + process.env.PHONEPE_SALT_KEY;
    const sha256 = crypto.createHash('sha256').update(string).digest('hex');
    const checksum = `${sha256}###${keyIndex}`;

    const response = await axios.get(
      `${process.env.PHONEPE_STATUS_URL || 'https://api-preprod.phonepe.com/apis/pg-sandbox/pg/v1/status'}/${merchantId}/${merchantTransactionId}`,
      {
        headers: {
          'Content-Type': 'application/json',
          'X-VERIFY': checksum,
          'X-MERCHANT-ID': merchantId,
          'accept': 'application/json'
        }
      }
    );

    if (response.data.success && response.data.data.responseCode === 'SUCCESS') {
      res.redirect(process.env.SUCCESS_URL || 'http://localhost:3000/success');
    } else {
      res.redirect(process.env.FAILURE_URL || 'http://localhost:3000/failure');
    }
  } catch (error) {
    console.error('Status check error:', error.message);
    res.status(500).json({ success: false, message: 'Error checking payment status' });
  }
});



app.post('/api/shiprocket/auth', async (req, res) => {
  try {
    const response = await axios.post(
      `${process.env.SHIPROCKET_URL}/auth/login`,
      {
        email: process.env.SHIPROCKET_EMAIL,
        password: process.env.SHIPROCKET_PASSWORD
      },
      { headers: { 'Content-Type': 'application/json' } }
    );

    res.json({ success: true, token: response.data.token });
  } catch (error) {
    console.error('Auth error:', error.message);
    res.status(500).json({ success: false, message: 'Authentication failed' });
  }
});

app.post('/api/shiprocket/create-order', async (req, res) => {
  try {
    const { order_id, order_date, pickup_location, billing, shipping, products, payment_method, sub_total, dimensions } = req.body;

    const token = req.headers.authorization?.split('Bearer ')[1];
    if (!token) return res.status(401).json({ success: false, message: 'Token required' });

    const orderData = {
      order_id,
      order_date,
      pickup_location,
      billing_customer_name: billing.name,
      billing_last_name: billing.last_name || '',
      billing_address: billing.address,
      billing_city: billing.city,
      billing_pincode: billing.pincode,
      billing_state: billing.state,
      billing_country: billing.country,
      billing_email: billing.email,
      billing_phone: billing.phone,
      shipping_is_billing: !shipping,
      shipping_customer_name: shipping?.name || '',
      shipping_address: shipping?.address || '',
      shipping_city: shipping?.city || '',
      shipping_pincode: shipping?.pincode || '',
      shipping_state: shipping?.state || '',
      shipping_country: shipping?.country || '',
      order_items: products,
      payment_method,
      sub_total,
      length: dimensions.length,
      breadth: dimensions.breadth,
      height: dimensions.height,
      weight: dimensions.weight
    };

    const response = await axios.post(
      `${process.env.SHIPROCKET_URL}/orders/create/adhoc`,
      orderData,
      {
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        }
      }
    );

    res.json({ success: true, data: response.data });
  } catch (error) {
    console.error('Order creation error:', error.message);
    res.status(500).json({ success: false, message: 'Order creation failed' });
  }
});

app.get('/track/:shipment_id', async (req, res) => {
  try {
    const { shipment_id } = req.params;
    const token = req.headers.authorization?.split('Bearer ')[1];
    if (!token) return res.status(401).json({ success: false, message: 'Token required' });

    const response = await axios.get(
      `${process.env.SHIPROCKET_URL}/courier/track/shipment/${shipment_id}`,
      {
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        }
      }
    );

    res.json({ success: true, data: response.data });
  } catch (error) {
    console.error('Tracking error:', error.message);
    res.status(500).json({ success: false, message: 'Tracking failed' });
  }
});


const generateChecksum = (payload, endpoint) => {
  const stringToHash = payload + endpoint + SALT_KEY;
  const sha256 = crypto.createHash('sha256').update(stringToHash).digest('hex');
  return `${sha256}###${SALT_INDEX}`;
};

// Endpoint to initiate payment
app.post('/api/initiate-payment', async (req, res) => {
  try {
    const { amount, userId, phone, name } = req.body;
    const merchantTransactionId = 'MT' + Date.now();

    const payload = {
      merchantId: MERCHANT_ID,
      merchantTransactionId: merchantTransactionId,
      merchantUserId: `MUID${userId}`,
      amount: amount * 100,
      redirectUrl: `${CALLBACK_URL}?transactionId=${merchantTransactionId}`,
      redirectMode: 'POST',
      callbackUrl: `${CALLBACK_URL}?transactionId=${merchantTransactionId}`,
      mobileNumber: phone,
      name: name,
      paymentInstrument: { type: 'PAY_PAGE' },
    };

    const payloadString = JSON.stringify(payload);
    const payloadBase64 = Buffer.from(payloadString).toString('base64');
    const stringToHash = payloadBase64 + '/pg/v1/pay' + SALT_KEY;
    const sha256 = crypto.createHash('sha256').update(stringToHash).digest('hex');
    const checksum = sha256 + '###' + SALT_INDEX;

    const options = {
      method: 'POST',
      url: PAYMENT_URL,
      headers: {
        accept: 'application/json',
        'Content-Type': 'application/json',
        'X-VERIFY': checksum,
      },
      data: { request: payloadBase64 },
    };

    const response = await axios.request(options);
    console.log('Payment Initiation Response:', JSON.stringify(response.data, null, 2));
    const redirectUrl = response.data.data.instrumentResponse.redirectInfo.url;

    res.json({ success: true, redirectUrl, merchantTransactionId });
  } catch (error) {
    console.error('Payment initiation error:', error.message);
    res.status(500).json({ success: false, message: 'Payment initiation failed' });
  }
});

// Payment callback endpoint
app.post('/api/payment/callback', async (req, res) => {
  try {
    const { transactionId } = req.query;
    if (!transactionId) {
      return res
        .status(400)
        .json({ success: false, message: 'Transaction ID is required' });
    }

    // Use standard sandbox status URL
    const statusUrl = `https://api-preprod.phonepe.com/apis/pg-sandbox/pg/v1/status/${MERCHANT_ID}/${transactionId}`;
    const endpoint = `/pg/v1/status/${MERCHANT_ID}/${transactionId}`;
    const checksum = generateChecksum('', endpoint);

    console.log('Status URL:', statusUrl);
    console.log('Endpoint for checksum:', endpoint);
    console.log('X-VERIFY:', checksum);

    const response = await axios.get(statusUrl, {
      headers: {
        'Content-Type': 'application/json',
        'X-VERIFY': checksum,
        'X-MERCHANT-ID': MERCHANT_ID,
        'accept': 'application/json',
      },
    });

    const paymentStatus = response.data.success
      ? process.env.SUCCESS_URL
      : process.env.FAILURE_URL;
    return res.redirect(paymentStatus);
  } catch (error) {
    console.error('Payment Status Verification Error:', error.response ? error.response.data : error.message);
    return res.redirect(process.env.FAILURE_URL || process.env.SUCCESS_URL);
  }
});












// Start Server
const port = process.env.PORT || 5000;
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});