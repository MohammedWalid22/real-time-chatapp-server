require('dotenv').config();

const http = require('http');
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const mongoSanitize = require('express-mongo-sanitize');
const hpp = require('hpp');
const cookieParser = require('cookie-parser');
const compression = require('compression');
const rateLimit = require('express-rate-limit');

const { createClient } = require('redis');
const { Server } = require('socket.io');

const connectDB = require('./config/db');
const logger = require('./utils/logger');
const errorHandler = require('./middleware/error.middleware');
const { authMiddleware } = require('./middleware/auth.middleware');

// Import routes
const authRoutes = require('./routes/auth.routes');
const userRoutes = require('./routes/user.routes');
const messageRoutes = require('./routes/message.routes');
const roomRoutes = require('./routes/room.routes');
const friendRoutes = require('./routes/friend.routes');

// Initialize app
const app = express();
const server = http.createServer(app);

console.log('📝 Starting server...');

// Connect to database
connectDB();

// Setup Redis
const redisClient = createClient({ 
  url: process.env.REDIS_URL || 'redis://localhost:6379' 
});

let redisConnected = false;

redisClient.connect()
  .then(() => {
    redisConnected = true;
    console.log('✅ Redis connected');
  })
  .catch(err => {
    console.warn('⚠️ Redis connection error:', err.message);
    console.warn('Continuing without Redis. Some features may be limited.');
  });

// Trust proxy if behind reverse proxy
app.set('trust proxy', 1);

// Security Middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      connectSrc: ["'self'", process.env.CLIENT_URL || 'http://localhost:3000'],
      imgSrc: ["'self'", "data:", "https:"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
    },
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
}));

app.use(cors({
  origin: process.env.CLIENT_URL || 'http://localhost:3000',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token']
}));

// Compression (before body parsing)
app.use(compression());

// Body parsing
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(cookieParser());

// Data sanitization
app.use(mongoSanitize()); // Prevent NoSQL injection

// HPP - Prevent HTTP Parameter Pollution
app.use(hpp());

// Request logging
app.use((req, res, next) => {
  logger.info(`${req.method} ${req.path} - ${req.ip}`);
  next();
});

// Rate limiting
const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW) || 15 * 60 * 1000,
  max: parseInt(process.env.RATE_LIMIT_MAX) || 100,
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

app.use('/api/', limiter);

// Stricter limit for auth endpoints
const authLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10, // 10 attempts
  skipSuccessfulRequests: true,
  message: 'Too many login attempts, please try again after an hour.'
});

app.use('/api/auth/login', authLimiter);
app.use('/api/auth/register', authLimiter);

// API Routes
app.use('/api/auth', authRoutes);
app.use('/api/users', authMiddleware, userRoutes);
app.use('/api/messages', authMiddleware, messageRoutes);
app.use('/api/rooms', authMiddleware, roomRoutes);
app.use('/api/friends', authMiddleware, friendRoutes);

// Health check
app.get('/health', (req, res) => {
  res.status(200).json({ 
    status: 'healthy', 
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ message: 'Route not found' });
});

// Global error handler
app.use(errorHandler);

// Socket.IO with security
const io = new Server(server, {
  cors: {
    origin: process.env.CLIENT_URL || 'http://localhost:3000',
    credentials: true
  },
  pingTimeout: 60000,
  pingInterval: 25000,
  transports: ['websocket', 'polling'], // Allow both for compatibility
  allowUpgrades: true,
  cookie: {
    name: 'io',
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict'
  }
});

// Make io accessible to controllers
app.set('io', io);

// Socket authentication middleware
io.use(async (socket, next) => {
  try {
    const token = socket.handshake.auth.token || 
                  socket.handshake.headers.authorization?.split(' ')[1];
    
    if (!token) {
      return next(new Error('Authentication error: No token provided'));
    }

    const jwt = require('jsonwebtoken');
    const decoded = jwt.verify(token, process.env.JWT_ACCESS_SECRET);
    
    const User = require('./models/User');
    const user = await User.findById(decoded.id).select('-password');
    
    if (!user) {
      return next(new Error('Authentication error: User not found'));
    }

    if (user.isBanned) {
      return next(new Error('Authentication error: User is banned'));
    }

    socket.user = user;
    socket.userId = user._id.toString();
    
    // Store in Redis for tracking (only if connected)
    if (redisConnected) {
      await redisClient.setEx(`socket:${user._id}`, 3600, socket.id);
    }
    
    next();
  } catch (err) {
    logger.error('Socket auth error:', err);
    next(new Error('Authentication failed'));
  }
});

// Socket connection handler
io.on('connection', (socket) => {
  logger.info(`User connected: ${socket.user.username} (${socket.userId})`);
  
  // Join personal room
  socket.join(socket.userId);
  
  // Update online status
  socket.broadcast.emit('user-status', {
    userId: socket.userId,
    status: 'online',
    username: socket.user.username
  });

  // Handle messages with encryption
  socket.on('send-message', async (data) => {
    try {
      const { roomId, content, type = 'text', replyTo } = data;
      
      // Validate input
      if (!content || content.length > 5000) {
        return socket.emit('error', { message: 'Invalid message' });
      }

      // Encrypt message content
      const { encryptMessage } = require('./services/encryption.service');
      const encryptedContent = encryptMessage(content, roomId);

      const Message = require('./models/Message');
      const message = await Message.create({
        room: roomId,
        sender: socket.userId,
        content: encryptedContent,
        type,
        replyTo,
        metadata: {
          encrypted: true,
          algorithm: 'AES-256-GCM'
        }
      });

      await message.populate('sender', 'username avatar');
      
      // Decrypt for sending to clients
      const decryptedMessage = {
        ...message.toObject(),
        content: content // Send original to sender/recipients
      };

      io.to(roomId).emit('new-message', decryptedMessage);
      
      // Update room's last message
      const Room = require('./models/Room');
      await Room.findByIdAndUpdate(roomId, { lastMessage: message._id });
      
    } catch (err) {
      logger.error('Send message error:', err);
      socket.emit('error', { message: 'Failed to send message' });
    }
  });

  // Handle typing
  socket.on('typing', (roomId) => {
    socket.to(roomId).emit('typing', {
      userId: socket.userId,
      username: socket.user.username,
      roomId
    });
  });

  socket.on('stop-typing', (roomId) => {
    socket.to(roomId).emit('stop-typing', {
      userId: socket.userId,
      roomId
    });
  });

  // Handle call signaling (WebRTC)
  socket.on('call-offer', (data) => {
    io.to(data.to).emit('call-offer', {
      from: socket.userId,
      offer: data.offer,
      type: data.type // 'video' or 'voice'
    });
  });

  socket.on('call-answer', (data) => {
    io.to(data.to).emit('call-answer', {
      from: socket.userId,
      answer: data.answer
    });
  });

  socket.on('ice-candidate', (data) => {
    io.to(data.to).emit('ice-candidate', {
      from: socket.userId,
      candidate: data.candidate
    });
  });

  socket.on('end-call', (data) => {
    io.to(data.to).emit('end-call', { from: socket.userId });
  });

  // Disconnect
  socket.on('disconnect', async () => {
    logger.info(`User disconnected: ${socket.user.username}`);
    
    // Remove from Redis (only if connected)
    if (redisConnected) {
      await redisClient.del(`socket:${socket.userId}`);
    }
    
    // Update last seen
    const User = require('./models/User');
    await User.findByIdAndUpdate(socket.userId, {
      status: 'offline',
      lastSeen: new Date()
    });

    socket.broadcast.emit('user-status', {
      userId: socket.userId,
      status: 'offline',
      lastSeen: new Date()
    });
  });
});

// Graceful shutdown
process.on('SIGTERM', async () => {
  logger.info('SIGTERM received, shutting down gracefully');
  server.close(() => {
    logger.info('Process terminated');
  });
});

// ========== START SERVER (مرة واحدة بس!) ==========
const PORT = process.env.PORT || 5000;

const { testConnection } = require('./services/email.service');

server.listen(PORT, () => {
  logger.info(`🚀 Server running on port ${PORT} in ${process.env.NODE_ENV || 'development'} mode`);
  logger.info(`🔒 Security: Helmet enabled, Rate limiting active, E2EE ready`);
  
  // Test email connection after server starts
  testConnection().then(connected => {
    if (connected) {
      console.log('📧 Email service is ready');
    } else {
      console.log('⚠️  Email service not available - check your .env configuration');
    }
  });
});

module.exports = { app, server, io, redisClient };