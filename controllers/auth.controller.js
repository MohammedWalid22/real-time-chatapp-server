const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const User = require('../models/User');
const RefreshToken = require('../models/RefreshToken');
const logger = require('../utils/logger');
const { sendVerificationEmail, sendOTPEmail, sendPasswordResetEmail } = require('../services/email.service');

const generateTokens = (userId) => {
  const accessToken = jwt.sign(
    { id: userId },
    process.env.JWT_ACCESS_SECRET,
    { expiresIn: process.env.JWT_ACCESS_EXPIRY || '15m' }
  );
  
  const refreshToken = jwt.sign(
    { id: userId },
    process.env.JWT_REFRESH_SECRET,
    { expiresIn: process.env.JWT_REFRESH_EXPIRY || '7d' }
  );
  
  return { accessToken, refreshToken };
};

// ========== REGISTER ==========
exports.register = async (req, res, next) => {
  try {
    const { username, email, password, verificationMethod = 'otp' } = req.body;
    
    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      return res.status(409).json({ 
        message: existingUser.email === email ? 'Email already registered' : 'Username already taken' 
      });
    }
    
    const user = await User.create({ username, email, password });
    
    // Choose verification method: 'otp' or 'link'
    if (verificationMethod === 'otp') {
      // ✅ NEW: OTP Method
      const otp = user.createEmailVerificationOTP();
      await user.save({ validateBeforeSave: false });
      
      try {
        await sendOTPEmail(user.email, user.username, otp, 'verification');
      } catch (emailError) {
        console.error('Failed to send OTP:', emailError);
      }
      
      logger.info(`New user registered (OTP): ${user.email}`);
      
      return res.status(201).json({
        success: true,
        message: 'Registration successful! Check your email for the 6-digit verification code.',
        data: {
          userId: user._id,
          email: user.email,
          requiresVerification: true,
          method: 'otp'
        }
      });
    } else {
      // ✅ ORIGINAL: Link Method
      const verifyToken = user.createEmailVerificationToken();
      await user.save({ validateBeforeSave: false });
      
      const verifyURL = `${process.env.CLIENT_URL}/verify-email/${verifyToken}`;
      
      try {
        await sendVerificationEmail(user.email, user.username, verifyURL);
      } catch (emailError) {
        console.error('Failed to send verification email:', emailError);
      }
      
      // Generate tokens (original behavior)
      const { accessToken, refreshToken } = generateTokens(user._id);
      
      await RefreshToken.create({
        token: refreshToken,
        user: user._id,
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
      });
      
      logger.info(`New user registered (Link): ${user.email}`);
      
      return res.status(201).json({
        success: true,
        message: 'Registration successful. Please verify your email.',
        accessToken,
        refreshToken,
        user: {
          id: user._id,
          username: user.username,
          email: user.email,
          isEmailVerified: user.isEmailVerified,
          method: 'link'
        }
      });
    }
    
  } catch (error) {
    next(error);
  }
};

// ========== VERIFY EMAIL WITH OTP (NEW) ==========
exports.verifyEmailWithOTP = async (req, res, next) => {
  try {
    const { email, otp } = req.body;
    
    if (!email || !otp) {
      return res.status(400).json({ 
        message: 'Email and OTP are required' 
      });
    }
    
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    if (user.isEmailVerified) {
      return res.status(400).json({ 
        message: 'Email already verified' 
      });
    }
    
    // Verify OTP
    const isValidOTP = user.verifyEmailOTP(otp);
    if (!isValidOTP) {
      return res.status(400).json({ 
        message: 'Invalid or expired verification code' 
      });
    }
    
    // Mark as verified and clear OTP
    user.isEmailVerified = true;
    user.emailVerificationOTP = undefined;
    await user.save({ validateBeforeSave: false });
    
    // Generate tokens after verification
    const { accessToken, refreshToken } = generateTokens(user._id);
    
    await RefreshToken.create({
      token: refreshToken,
      user: user._id,
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
    });
    
    logger.info(`Email verified with OTP: ${user.email}`);
    
    res.json({
      success: true,
      message: 'Email verified successfully!',
      accessToken,
      refreshToken,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        isEmailVerified: true
      }
    });
    
  } catch (error) {
    next(error);
  }
};

// ========== VERIFY EMAIL WITH LINK (ORIGINAL) ==========
exports.verifyEmail = async (req, res, next) => {
  try {
    const { token } = req.params;
    
    // Hash the token
    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');
    
    // Find user with this token
    const user = await User.findOne({
      emailVerificationToken: hashedToken,
      emailVerificationExpires: { $gt: Date.now() }
    });
    
    if (!user) {
      return res.status(400).json({ message: 'Invalid or expired verification token' });
    }
    
    // Mark email as verified
    user.isEmailVerified = true;
    user.emailVerificationToken = undefined;
    user.emailVerificationExpires = undefined;
    await user.save({ validateBeforeSave: false });
    
    logger.info(`Email verified with link: ${user.email}`);
    
    res.json({ 
      success: true,
      message: 'Email verified successfully' 
    });
    
  } catch (error) {
    next(error);
  }
};

// ========== RESEND OTP (NEW) ==========
exports.resendOTP = async (req, res, next) => {
  try {
    const { email, type = 'verification' } = req.body;
    
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    if (type === 'verification' && user.isEmailVerified) {
      return res.status(400).json({ message: 'Email already verified' });
    }
    
    // Generate new OTP
    const otp = user.createEmailVerificationOTP();
    await user.save({ validateBeforeSave: false });
    
    try {
      await sendOTPEmail(user.email, user.username, otp, type);
      logger.info(`OTP resent to: ${user.email} (${type})`);
    } catch (emailError) {
      console.error('Failed to resend OTP:', emailError);
      return res.status(500).json({ message: 'Failed to send email' });
    }
    
    res.json({ 
      success: true,
      message: 'Verification code sent! Check your email.' 
    });
    
  } catch (error) {
    next(error);
  }
};

// ========== RESEND VERIFICATION LINK (ORIGINAL) ==========
exports.resendVerification = async (req, res, next) => {
  try {
    const { email } = req.body;
    
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    if (user.isEmailVerified) {
      return res.status(400).json({ message: 'Email already verified' });
    }
    
    // Generate new verification token
    const verifyToken = user.createEmailVerificationToken();
    await user.save({ validateBeforeSave: false });
    
    // Send email
    const verifyUrl = `${process.env.CLIENT_URL}/verify-email/${verifyToken}`;
    
    try {
      await sendVerificationEmail(user.email, user.username, verifyUrl);
      logger.info(`Verification link resent to: ${user.email}`);
    } catch (emailError) {
      console.error('Failed to resend verification email:', emailError);
      return res.status(500).json({ message: 'Failed to send email' });
    }
    
    res.json({ 
      success: true,
      message: 'Verification email sent' 
    });
    
  } catch (error) {
    next(error);
  }
};

// ========== LOGIN ==========
exports.login = async (req, res, next) => {
  try {
    const { email, password, twoFactorCode } = req.body;
    
    const user = await User.findOne({ email }).select('+password +twoFactorSecret +loginAttempts +lockUntil');
    
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    
    if (user.isLocked()) {
      return res.status(423).json({ 
        message: 'Account is locked. Please try again later.',
        lockUntil: user.lockUntil
      });
    }
    
    const isPasswordValid = await user.comparePassword(password);
    
    if (!isPasswordValid) {
      await user.incLoginAttempts();
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    
    // Check 2FA
    if (user.twoFactorEnabled) {
      if (!twoFactorCode) {
        return res.status(403).json({ 
          message: '2FA required',
          twoFactorRequired: true 
        });
      }
      
      const verified = speakeasy.totp.verify({
        secret: user.twoFactorSecret,
        encoding: 'base32',
        token: twoFactorCode,
        window: 1
      });
      
      if (!verified) {
        return res.status(401).json({ message: 'Invalid 2FA code' });
      }
    }
    
    // Reset login attempts
    if (user.loginAttempts > 0) {
      await user.updateOne({
        $set: { loginAttempts: 0 },
        $unset: { lockUntil: 1 }
      });
    }
    
    // Generate tokens
    const { accessToken, refreshToken } = generateTokens(user._id);
    
    // Save refresh token
    await RefreshToken.create({
      token: refreshToken,
      user: user._id,
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      deviceInfo: req.headers['user-agent'],
      ipAddress: req.ip
    });
    
    // Update user status
    user.status = 'online';
    await user.save({ validateBeforeSave: false });
    
    logger.info(`User logged in: ${user.email}`);
    
    res.json({
      success: true,
      accessToken,
      refreshToken,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        avatar: user.avatar,
        isEmailVerified: user.isEmailVerified,
        twoFactorEnabled: user.twoFactorEnabled
      }
    });
    
  } catch (error) {
    next(error);
  }
};

// ========== REFRESH TOKEN ==========
exports.refresh = async (req, res, next) => {
  try {
    const { refreshToken } = req.body;
    
    if (!refreshToken) {
      return res.status(401).json({ message: 'Refresh token required' });
    }
    
    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    
    const tokenDoc = await RefreshToken.findOne({ 
      token: refreshToken,
      user: decoded.id,
      revoked: false
    });
    
    if (!tokenDoc || tokenDoc.expiresAt < Date.now()) {
      return res.status(401).json({ message: 'Invalid or expired refresh token' });
    }
    
    const tokens = generateTokens(decoded.id);
    
    tokenDoc.revoked = true;
    await tokenDoc.save();
    
    await RefreshToken.create({
      token: tokens.refreshToken,
      user: decoded.id,
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
    });
    
    res.json(tokens);
    
  } catch (error) {
    next(error);
  }
};

// ========== LOGOUT ==========
exports.logout = async (req, res, next) => {
  try {
    const { refreshToken } = req.body;
    
    await RefreshToken.findOneAndUpdate(
      { token: refreshToken },
      { revoked: true }
    );
    
    await User.findByIdAndUpdate(req.user.id, {
      status: 'offline',
      lastSeen: new Date()
    });
    
    res.json({ message: 'Logged out successfully' });
    
  } catch (error) {
    next(error);
  }
};

// ========== 2FA ==========
exports.setup2FA = async (req, res, next) => {
  try {
    const user = await User.findById(req.user.id).select('+twoFactorSecret');
    
    const secret = speakeasy.generateSecret({
      name: `ChatApp:${user.email}`
    });
    
    user.twoFactorSecret = secret.base32;
    await user.save({ validateBeforeSave: false });
    
    const qrCodeUrl = await qrcode.toDataURL(secret.otpauth_url);
    
    res.json({
      secret: secret.base32,
      qrCode: qrCodeUrl
    });
    
  } catch (error) {
    next(error);
  }
};

exports.verify2FA = async (req, res, next) => {
  try {
    const { code } = req.body;
    const user = await User.findById(req.user.id).select('+twoFactorSecret');
    
    const verified = speakeasy.totp.verify({
      secret: user.twoFactorSecret,
      encoding: 'base32',
      token: code,
      window: 1
    });
    
    if (!verified) {
      return res.status(400).json({ message: 'Invalid verification code' });
    }
    
    user.twoFactorEnabled = true;
    await user.save({ validateBeforeSave: false });
    
    res.json({ message: '2FA enabled successfully' });
    
  } catch (error) {
    next(error);
  }
};

exports.disable2FA = async (req, res, next) => {
  try {
    const { password } = req.body;
    const user = await User.findById(req.user.id).select('+password');
    
    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid password' });
    }
    
    user.twoFactorEnabled = false;
    user.twoFactorSecret = undefined;
    await user.save({ validateBeforeSave: false });
    
    res.json({ message: '2FA disabled successfully' });
    
  } catch (error) {
    next(error);
  }
};

// ========== PASSWORD RESET WITH OTP (NEW) ==========
exports.forgotPasswordWithOTP = async (req, res, next) => {
  try {
    const { email } = req.body;
    
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    // Generate OTP for password reset
    const otp = user.createPasswordResetOTP();
    await user.save({ validateBeforeSave: false });
    
    await sendOTPEmail(user.email, user.username, otp, 'password-reset');
    
    logger.info(`Password reset OTP sent to: ${user.email}`);
    
    res.json({ 
      success: true,
      message: 'Password reset code sent to your email' 
    });
    
  } catch (error) {
    next(error);
  }
};

exports.resetPasswordWithOTP = async (req, res, next) => {
  try {
    const { email, otp, newPassword } = req.body;
    
    const user = await User.findOne({ email }).select('+passwordResetOTP');
    
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    // Verify OTP
    const isValidOTP = user.verifyPasswordResetOTP(otp);
    if (!isValidOTP) {
      return res.status(400).json({ message: 'Invalid or expired code' });
    }
    
    // Update password
    user.password = newPassword;
    user.passwordResetOTP = undefined;
    await user.save({ validateBeforeSave: false });
    
    logger.info(`Password reset with OTP: ${user.email}`);
    
    res.json({ 
      success: true,
      message: 'Password reset successfully' 
    });
    
  } catch (error) {
    next(error);
  }
};

// ========== PASSWORD RESET WITH LINK (ORIGINAL) ==========
exports.forgotPassword = async (req, res, next) => {
  try {
    const { email } = req.body;
    
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    // Generate password reset token
    const resetToken = user.createPasswordResetToken();
    await user.save({ validateBeforeSave: false });
    
    // Send email
    const resetUrl = `${process.env.CLIENT_URL}/reset-password/${resetToken}`;
    
    try {
      await sendPasswordResetEmail(user.email, user.username, resetUrl);
      logger.info(`Password reset link sent to: ${user.email}`);
    } catch (emailError) {
      console.error('Failed to send password reset email:', emailError);
      return res.status(500).json({ message: 'Failed to send email' });
    }
    
    res.json({ 
      success: true,
      message: 'Password reset email sent' 
    });
    
  } catch (error) {
    next(error);
  }
};

exports.resetPassword = async (req, res, next) => {
  try {
    const { token } = req.params;
    const { password } = req.body;
    
    // Hash the token
    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');
    
    // Find user with this token
    const user = await User.findOne({
      passwordResetToken: hashedToken,
      passwordResetExpires: { $gt: Date.now() }
    });
    
    if (!user) {
      return res.status(400).json({ message: 'Invalid or expired reset token' });
    }
    
    // Update password
    user.password = password;
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save({ validateBeforeSave: false });
    
    logger.info(`Password reset with link: ${user.email}`);
    
    res.json({ 
      success: true,
      message: 'Password reset successfully' 
    });
    
  } catch (error) {
    next(error);
  }
};