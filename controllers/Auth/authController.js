const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const SECRET_KEY = process.env.JWT_SECRET;
const { Op } = require('sequelize');
const User = require('../../models/Auth/adminModel');

// Helper function to validate environment variables
const validateEnvVariables = () => {
  if (!process.env.JWT_SECRET) {
    throw new Error('JWT_SECRET is not defined in the environment variables');
  }
};

// Helper function to generate JWT tokens
const generateToken = (userId) => {
  return jwt.sign(
    { userId },
    SECRET_KEY,
    {
      algorithm: 'HS256',
      expiresIn: '24h'
    }
  );
};

// Validate JWT_SECRET at startup
validateEnvVariables();
const signup = async (req, res) => {
  try {
    const { userName, email, password, phone, dob } = req.body.formData;

    // Check if user exists
    const existingUser = await User.findOne({
      where: {
        [Op.or]: [
          { user_email: email },
          { user_mobile: phone }
        ]
      }
    });

    if (existingUser) {
      return res.status(400).json({
        message: existingUser.user_email === email
          ? 'Email already registered'
          : 'Phone number already registered',
      });
    }

    // Create new user (plain password → model hook will hash it)
    const user = await User.create({
      username: userName,
      user_email: email,
      user_password: password,   // 👈 plain text here, hook hashes
      user_mobile: phone,
      dob_day: dob.day,
      dob_month: dob.month,
      dob_year: dob.year,
    });

    // Generate JWT token
    const token = jwt.sign({ userId: user.user_id }, SECRET_KEY, {
      algorithm: 'HS256',
      issuer: 'wistar-auth',
      audience: 'wistar-api',
      expiresIn: '24h',
    });

    await user.update({
      token,
      token_created: new Date()
    });

    res.status(201).json({
      message: 'User registered successfully',
      token,
      user: {
        id: user.user_id,
        username: user.username,
        email: user.user_email,
        phone: user.user_mobile,
      },
    });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
};

const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find user
    const user = await User.findOne({ where: { user_email: email } });

    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Verify password
    const isValidPassword = await bcrypt.compare(password, user.user_password);
    if (!isValidPassword) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Generate JWT token
    const token = jwt.sign({ userId: user.user_id }, SECRET_KEY, {
      algorithm: 'HS256',
      issuer: 'wistar-auth',
      audience: 'wistar-api',
      expiresIn: '24h',
    });

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user.user_id,
        username: user.username,
        email: user.user_email,
        phone: user.user_mobile,
      },
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
};



const verifyToken = async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ message: 'Authorization header missing or malformed' });
    }

    const token = authHeader.split(' ')[1];
    
    // First try to decode the token to check its type
    const decodedHeader = jwt.decode(token, { complete: true });
    if (!decodedHeader) {
      return res.status(401).json({ message: 'Invalid token format' });
    }

    let user;
    if (decodedHeader.header.alg === 'RS256') {
      // Firebase token
      const firebaseUid = decodedHeader.payload.user_id || decodedHeader.payload.sub;
      user = await User.findOne({
        where: { uid: firebaseUid },
        attributes: ['id', 'firstName', 'lastName', 'email', 'profile_url']
      });
    } else {
      // Local JWT token
      const decoded = jwt.decode(token, SECRET_KEY);
      user = await User.findByPk(decoded.userId, {
        attributes: ['id', 'firstName', 'lastName', 'email']
      });
    }

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    return res.status(200).json({ user });
  } catch (error) {
    console.error('Token verification error:', error);
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ message: 'Token has expired' });
    }
    return res.status(401).json({ 
      message: 'Invalid token',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};



const googleSignup = async (req, res) => {
  try {
    const { email, firstname, lastname, profile_url, auth_provider, uid } =
      req.body;

    const existingUser = await User.findOne({ where: { email } });

    if (existingUser) {
      return res.status(400).json({
        message: 'Email already registered. Please use Google login instead.',
      });
    }

    const user = await User.create({
      firstName: firstname,
      lastName: lastname,
      email,
      profile_url,
      auth_provider,
      uid,
    });

    const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, {
      expiresIn: '240h',
    });

    res.status(201).json({
      message: 'Google signup successful',
      token,
      user: {
        id: user.id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        profile_url: user.profile_url,
      },
    });
  } catch (error) {
    console.error('Google signup error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
};

const googleLogin = async (req, res) => {
  try {
    const { email, uid } = req.body;

    const user = await User.findOne({
      where: { email, auth_provider: 'google.com', uid },
    });

    if (!user) {
      return res.status(404).json({
        message: 'No account found. Please sign up with Google first.',
      });
    }

    const token = jwt.sign({ userId: user.id }, SECRET_KEY, {
      algorithm: 'HS256',
      issuer: 'make-my-book-auth',
      audience: 'make-my-book-api', // Set audience
      expiresIn: '24h', // You can add expiry if needed
    });

    res.json({
      message: 'Google login successful',
      token,
      user: {
        id: user.id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        profile_url: user.profile_url,
      },
    });
  } catch (error) {
    console.error('Google login error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
};

const phoneSignup = async (req, res) => {
  try {
    const { phone, firstName, lastName, password } = req.body;

    const existingUser = await User.findOne({ where: { phone } });

    if (existingUser) {
      return res.status(400).json({
        message: 'Phone number already registered. Please login instead.',
      });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const user = await User.create({
      firstName,
      lastName,
      phone,
      password: hashedPassword,
      auth_provider: 'phone',
    });

    const token = jwt.sign({ userId: 4 }, SECRET_KEY, {
      algorithm: 'HS256',
      issuer: 'make-my-book-auth',
      audience: 'make-my-book-api', // Set audience
      expiresIn: '24h', // You can add expiry if needed
    });

    res.status(201).json({
      message: 'Phone signup successful',
      token,
      user: {
        id: user.id,
        firstName: user.firstName,
        lastName: user.lastName,
        phone: user.phone,
      },
    });
  } catch (error) {
    console.error('Phone signup error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
};

const phoneLogin = async (req, res) => {
  try {
    const { phone, password } = req.body;

    const user = await User.findOne({
      where: { phone, auth_provider: 'phone' },
    });

    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const token = generateToken(user.id);



    res.json({
      message: 'Phone login successful',
      token,
      user: {
        id: user.id,
        firstName: user.firstName,
        lastName: user.lastName,
        phone: user.phone,
      },
    });
  } catch (error) {
    console.error('Phone login error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
};

module.exports = {
  signup,
  login,
  verifyToken,
  googleSignup,
  googleLogin,
  phoneSignup,
  phoneLogin,
};