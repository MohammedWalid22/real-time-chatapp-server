const express = require('express');
const router = express.Router();
const { body } = require('express-validator');
const authController = require('../controllers/auth.controller');
const { authMiddleware } = require('../middleware/auth.middleware');

// Validation middleware
const registerValidation = [
  body('username')
    .trim()
    .isLength({ min: 3, max: 30 })
    .matches(/^[a-zA-Z0-9_]+$/)
    .withMessage('Username must be 3-30 characters, alphanumeric and underscores only'),
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Please provide a valid email'),
  body('password')
    .isLength({ min: 8 })
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .withMessage('Password must be at least 8 characters with uppercase, lowercase, number and special character')
];

const loginValidation = [
  body('email').isEmail().normalizeEmail(),
  body('password').notEmpty()
];

// Routes
router.post('/register', registerValidation, authController.register);
router.post('/login', loginValidation, authController.login);
router.post('/refresh', authController.refresh);
router.post('/logout', authMiddleware, authController.logout);

// 2FA routes
router.post('/2fa/setup', authMiddleware, authController.setup2FA);
router.post('/2fa/verify', authMiddleware, authController.verify2FA);
router.post('/2fa/disable', authMiddleware, authController.disable2FA);

// ✅ ORIGINAL: Email verification with link
router.get('/verify-email/:token', authController.verifyEmail);
router.post('/resend-verification', authController.resendVerification);

// ✅ NEW: Email verification with OTP
router.post('/verify-email-otp', authController.verifyEmailWithOTP);
router.post('/resend-otp', authController.resendOTP);

// ✅ ORIGINAL: Password reset with link
router.post('/forgot-password', authController.forgotPassword);
router.patch('/reset-password/:token', authController.resetPassword);

// ✅ NEW: Password reset with OTP
router.post('/forgot-password-otp', authController.forgotPasswordWithOTP);
router.post('/reset-password-otp', authController.resetPasswordWithOTP);

module.exports = router;