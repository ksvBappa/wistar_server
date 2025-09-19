const jwt = require('jsonwebtoken');
const SECRET_KEY = "sT0dHCZ3aG9cxw2j";

if (!SECRET_KEY) {
  throw new Error('JWT_SECRET is not defined in environment variables');
}

/**
 * Authentication middleware to protect routes
 * @param {import('express').Request} req - Express request object
 * @param {import('express').Response} res - Express response object
 * @param {import('express').NextFunction} next - Express next function
 */
const authenticate = (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];

    const token = authHeader.slice(7); // Remove 'Bearer ' prefix

    const decoded = jwt.verify(token, SECRET_KEY, {
      issuer: 'make-my-book-auth',
      audience: 'make-my-book-api', 
      algorithms: ['HS256']
    });

    req.user = decoded;
    console.log('Decoded token:');
    next();
  } catch (error) {

    console.error('Token verification error:', error);

    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ message: 'Token has expired' });
    }

    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({
        message: 'Invalid token',
        details: process.env.NODE_ENV === 'development' ? error.message : undefined
      });
    }

    return res.status(401).json({ message: 'Token verification failed' });
  }
};

module.exports = authenticate;
