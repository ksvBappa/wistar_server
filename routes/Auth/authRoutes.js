const express = require('express');
const router = express.Router();
const { 
  signup, 
  login, 
  verifyToken, 
  googleSignup,
  googleLogin,
  phoneSignup,
  phoneLogin
} = require('../../controllers/Auth/authController');
const authMiddleware = require('../../middlewares/authMiddleware');

// Public routes
router.post('/signup', signup);
router.post('/login', login);

// Google authentication routes
router.post('/google/signup', googleSignup);
router.post('/google/login', googleLogin);

// Phone authentication routes
router.post('/phone/signup', phoneSignup);
router.post('/phone/login', phoneLogin);

// Protected routes
router.get('/verify-token', verifyToken);

module.exports = router;
