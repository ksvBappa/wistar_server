const express = require('express');
const router = express.Router();
const { login, verifyToken, getProfile } = require('../../controllers/Auth/adminController');

router.post('/login', login);
router.get('/profile', verifyToken, getProfile);

module.exports = router;