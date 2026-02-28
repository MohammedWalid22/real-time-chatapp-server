const jwt = require('jsonwebtoken');
const User = require('../models/User');
const logger = require('../utils/logger');

// Authentication Middleware
exports.authMiddleware = async (req, res, next) => {
  try {
    // Get token from headers
    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }
    
    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_ACCESS_SECRET);
    
    // Get user from database
    const user = await User.findById(decoded.id).select('-password');
    
    if (!user) {
      return res.status(401).json({ message: 'User not found' });
    }
    
    if (user.isBanned) {
      return res.status(403).json({ message: 'User is banned' });
    }
    
    // Attach user to request
    req.user = user;
    next();
    
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ message: 'Token expired' });
    }
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({ message: 'Invalid token' });
    }
    next(error);
  }
};

// Optional Auth Middleware (doesn't fail if no token)
exports.optionalAuthMiddleware = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    
    if (token) {
      const decoded = jwt.verify(token, process.env.JWT_ACCESS_SECRET);
      const user = await User.findById(decoded.id).select('-password');
      
      if (user && !user.isBanned) {
        req.user = user;
      }
    }
    next();
    
  } catch (error) {
    // Silently fail - user is optional
    next();
  }
};

// Admin only middleware
exports.adminOnlyMiddleware = (req, res, next) => {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Admin access required' });
  }
  next();
};

// Owner or admin middleware
exports.ownerOrAdminMiddleware = (targetUserId) => {
  return (req, res, next) => {
    if (req.user._id.toString() !== targetUserId && req.user.role !== 'admin') {
      return res.status(403).json({ message: 'Unauthorized' });
    }
    next();
  };
};
