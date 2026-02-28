const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: [true, 'Username is required'],
    unique: true,
    trim: true,
    minlength: [3, 'Username must be at least 3 characters'],
    maxlength: [30, 'Username cannot exceed 30 characters'],
    match: [/^[a-zA-Z0-9_]+$/, 'Username can only contain letters, numbers, and underscores']
  },
  email: {
    type: String,
    required: [true, 'Email is required'],
    unique: true,
    lowercase: true,
    trim: true,
    match: [/^\S+@\S+\.\S+$/, 'Please enter a valid email']
  },
  password: {
    type: String,
    required: [true, 'Password is required'],
    minlength: [8, 'Password must be at least 8 characters'],
    select: false // Never include password in queries by default
  },
  avatar: {
    type: String,
    default: ''
  },
  status: {
    type: String,
    enum: ['online', 'offline', 'busy', 'away'],
    default: 'offline'
  },
  lastSeen: {
    type: Date,
    default: Date.now()
  },
  
  // ✅ إضافة friends array
  friends: [{
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    status: {
      type: String,
      enum: ['pending', 'accepted', 'blocked'],
      default: 'pending'
    },
    addedAt: {
      type: Date,
      default: Date.now
    }
  }],
  
  // ✅ إضافة isActive
  isActive: {
    type: Boolean,
    default: true
  },
  
  // Security fields
  isEmailVerified: {
    type: Boolean,
    default: false
  },
  
  // Token-based verification (for link method)
  emailVerificationToken: String,
  emailVerificationExpires: Date,
  
  // ✅ NEW: OTP-based verification (for code method)
  emailVerificationOTP: {
    code: String,
    expiresAt: Date
  },
  
  // ✅ NEW: Password reset OTP
  passwordResetOTP: {
    code: String,
    expiresAt: Date
  },
  
  passwordChangedAt: Date,
  passwordResetToken: String,
  passwordResetExpires: Date,
  
  twoFactorSecret: {
    type: String,
    select: false
  },
  twoFactorEnabled: {
    type: Boolean,
    default: false
  },
  
  loginAttempts: {
    type: Number,
    default: 0
  },
  lockUntil: Date,
  
  isBanned: {
    type: Boolean,
    default: false
  },
  banReason: String,
  
  // E2EE
  publicKey: {
    type: String,
    default: null
  },
  
  // Device tracking
  devices: [{
    deviceId: String,
    deviceName: String,
    lastLogin: Date,
    ipAddress: String
  }],
  
  // Privacy settings
  privacySettings: {
    lastSeenVisibility: {
      type: String,
      enum: ['everyone', 'contacts', 'nobody'],
      default: 'everyone'
    },
    profilePhotoVisibility: {
      type: String,
      enum: ['everyone', 'contacts', 'nobody'],
      default: 'everyone'
    },
    readReceipts: {
      type: Boolean,
      default: true
    }
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Indexes for performance
userSchema.index({ status: 1 });

// Hash password before saving
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  
  this.password = await bcrypt.hash(this.password, parseInt(process.env.BCRYPT_ROUNDS) || 12);
  
  if (!this.isNew) {
    this.passwordChangedAt = Date.now() - 1000;
  }
  
  next();
});

// Compare password method
userSchema.methods.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

// ✅ تعديل اسم الميثود لـ changedPasswordAfter
userSchema.methods.changedPasswordAfter = function(JWTTimestamp) {
  if (this.passwordChangedAt) {
    const changedTimestamp = parseInt(this.passwordChangedAt.getTime() / 1000, 10);
    return JWTTimestamp < changedTimestamp;
  }
  return false;
};

// Account lock check
userSchema.methods.isLocked = function() {
  return !!(this.lockUntil && this.lockUntil > Date.now());
};

// Increment login attempts
userSchema.methods.incLoginAttempts = async function() {
  if (this.lockUntil && this.lockUntil < Date.now()) {
    return this.updateOne({
      $set: { loginAttempts: 1 },
      $unset: { lockUntil: 1 }
    });
  }
  
  const updates = { $inc: { loginAttempts: 1 } };
  const maxAttempts = 5;
  const lockTime = 2 * 60 * 60 * 1000; // 2 hours
  
  if (this.loginAttempts + 1 >= maxAttempts && !this.isLocked()) {
    updates.$set = { lockUntil: Date.now() + lockTime };
  }
  
  return this.updateOne(updates);
};

// Generate password reset token (for link method)
userSchema.methods.createPasswordResetToken = function() {
  const resetToken = crypto.randomBytes(32).toString('hex');
  
  this.passwordResetToken = crypto
    .createHash('sha256')
    .update(resetToken)
    .digest('hex');
    
  this.passwordResetExpires = Date.now() + 10 * 60 * 1000; // 10 minutes
  
  return resetToken;
};

// Generate email verification token (for link method)
userSchema.methods.createEmailVerificationToken = function() {
  const verifyToken = crypto.randomBytes(32).toString('hex');
  
  this.emailVerificationToken = crypto
    .createHash('sha256')
    .update(verifyToken)
    .digest('hex');
    
  this.emailVerificationExpires = Date.now() + 24 * 60 * 60 * 1000; // 24 hours
  
  return verifyToken;
};

// ✅ NEW: Generate 6-digit OTP for email verification
userSchema.methods.createEmailVerificationOTP = function() {
  // Generate random 6-digit number (100000 - 999999)
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  
  this.emailVerificationOTP = {
    code: otp,
    expiresAt: Date.now() + 10 * 60 * 1000 // 10 minutes
  };
  
  return otp;
};

// ✅ NEW: Verify email OTP
userSchema.methods.verifyEmailOTP = function(inputOTP) {
  if (!this.emailVerificationOTP || !this.emailVerificationOTP.code) {
    return false;
  }
  
  // Check if expired
  if (Date.now() > this.emailVerificationOTP.expiresAt) {
    return false;
  }
  
  // Compare OTP (constant time comparison for security)
  const inputBuffer = Buffer.from(inputOTP);
  const storedBuffer = Buffer.from(this.emailVerificationOTP.code);
  
  if (inputBuffer.length !== storedBuffer.length) {
    return false;
  }
  
  return crypto.timingSafeEqual(inputBuffer, storedBuffer);
};

// ✅ NEW: Generate password reset OTP
userSchema.methods.createPasswordResetOTP = function() {
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  
  this.passwordResetOTP = {
    code: otp,
    expiresAt: Date.now() + 10 * 60 * 1000 // 10 minutes
  };
  
  return otp;
};

// ✅ NEW: Verify password reset OTP
userSchema.methods.verifyPasswordResetOTP = function(inputOTP) {
  if (!this.passwordResetOTP || !this.passwordResetOTP.code) {
    return false;
  }
  
  if (Date.now() > this.passwordResetOTP.expiresAt) {
    return false;
  }
  
  const inputBuffer = Buffer.from(inputOTP);
  const storedBuffer = Buffer.from(this.passwordResetOTP.code);
  
  if (inputBuffer.length !== storedBuffer.length) {
    return false;
  }
  
  return crypto.timingSafeEqual(inputBuffer, storedBuffer);
};

module.exports = mongoose.model('User', userSchema);