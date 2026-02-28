const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const mongoSanitize = require('express-mongo-sanitize');
const hpp = require('hpp');
const cors = require('cors');

// CORS configuration
exports.corsConfig = cors({
  origin: process.env.CLIENT_URL || 'http://localhost:3000',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'X-Requested-With',
    'Accept',
    'Origin'
  ],
  exposedHeaders: ['X-Total-Count', 'X-Rate-Limit']
});

// Security headers with Helmet
exports.helmetConfig = helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      connectSrc: ["'self'", process.env.CLIENT_URL || 'http://localhost:3000'],
      imgSrc: ["'self'", "data:", "https:", "blob:"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      fontSrc: ["'self'", "https:", "data:"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'", "blob:"],
      frameSrc: ["'none'"],
      upgradeInsecureRequests: [],
    },
  },
  crossOriginEmbedderPolicy: false,
  crossOriginResourcePolicy: { policy: "cross-origin" },
  dnsPrefetchControl: { allow: false },
  frameguard: { action: 'deny' },
  hidePoweredBy: true,
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  },
  ieNoOpen: true,
  noSniff: true,
  originAgentCluster: true,
  permittedCrossDomainPolicies: { permittedPolicies: 'none' },
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  xssFilter: true
});

// Data sanitization against NoSQL query injection
exports.mongoSanitizeConfig = mongoSanitize({
  replaceWith: '_',
  onSanitize: ({ req, key }) => {
    console.warn(`Sanitized key: ${key} from IP: ${req.ip}`);
  }
});

// ✅ شيلت xss-clean لأنها deprecated
// بدالها هنستخدم express-validator في الـ routes

// Prevent parameter pollution
exports.hppConfig = hpp({
  whitelist: [
    'sort',
    'page',
    'limit',
    'fields',
    'status',
    'type'
  ]
});

// Strict rate limiting for sensitive endpoints
exports.strictLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10,
  message: {
    success: false,
    message: 'Too many attempts, please try again after an hour'
  },
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: false,
  keyGenerator: (req) => req.ip
});

// API rate limiting
exports.apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  message: {
    success: false,
    message: 'Too many requests from this IP, please try again later'
  },
  standardHeaders: true,
  legacyHeaders: false
});

// File upload rate limiting
exports.uploadLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 50,
  message: {
    success: false,
    message: 'Upload limit exceeded, please try again later'
  }
});

// Request size limiter
exports.requestSizeLimiter = (req, res, next) => {
  const contentLength = parseInt(req.headers['content-length'] || 0);
  const maxSize = 10 * 1024 * 1024; // 10MB

  if (contentLength > maxSize) {
    return res.status(413).json({
      success: false,
      message: 'Request entity too large'
    });
  }
  next();
};

// IP whitelist/blacklist check
exports.ipFilter = (req, res, next) => {
  const blockedIPs = process.env.BLOCKED_IPS?.split(',') || [];
  const clientIP = req.ip || req.connection.remoteAddress;

  if (blockedIPs.includes(clientIP)) {
    return res.status(403).json({
      success: false,
      message: 'Access denied'
    });
  }
  next();
};

// Request timestamp validation (prevent replay attacks)
exports.timestampValidation = (req, res, next) => {
  const timestamp = parseInt(req.headers['x-request-timestamp']);
  const now = Date.now();
  const maxAge = 5 * 60 * 1000; // 5 minutes

  if (!timestamp || Math.abs(now - timestamp) > maxAge) {
    return res.status(400).json({
      success: false,
      message: 'Invalid or expired request timestamp'
    });
  }
  next();
};

// Security audit logging
exports.auditLogger = (req, res, next) => {
  const sensitiveEndpoints = ['/api/auth/login', '/api/auth/register', '/api/users/password'];
  
  if (sensitiveEndpoints.some(endpoint => req.path.includes(endpoint))) {
    const auditLog = {
      timestamp: new Date().toISOString(),
      ip: req.ip,
      method: req.method,
      path: req.path,
      userAgent: req.headers['user-agent'],
      userId: req.user?.id || 'anonymous'
    };
    
    console.log('[SECURITY AUDIT]', JSON.stringify(auditLog));
  }
  next();
};