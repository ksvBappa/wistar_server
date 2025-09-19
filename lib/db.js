// Import necessary modules
const { Sequelize } = require('sequelize');

// Load environment variables from .env file
require('dotenv').config();  // Ensure dotenv is loaded

// Initialize Sequelize with MySQL connection details
const sequelize = new Sequelize({
  host: process.env.DB_HOST || 'localhost',  // Use the DB_HOST value from .env (default to localhost)
  port: process.env.DB_PORT ,         // Add this line for port configuration
  dialect: 'mysql',                          // Using MySQL
  database: process.env.DB_NAME || 'wistar_db',    // DB name from .env or default to 'make_my_book'
  username: process.env.DB_USER || 'root',   // DB user from .env (default to 'root')
  password: process.env.DB_PASSWORD || '',   // DB password from .env (empty if not set)
  logging: false,                            // Disable SQL query logging (set to true to debug)
});

// Test the connection
sequelize.authenticate()
  .then(() => {
    console.log('Database connected successfully!');
  })
  .catch((err) => {
    console.error('Database connection error:', err);
  });

// Export the sequelize instance for use in your models
module.exports = sequelize;
