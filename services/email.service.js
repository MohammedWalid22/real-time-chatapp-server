const nodemailer = require('nodemailer');

// Create Gmail transporter
const createTransporter = () => {
  // Check if env vars exist
  if (!process.env.GMAIL_USER || !process.env.GMAIL_APP_PASSWORD) {
    console.error('❌ Missing GMAIL_USER or GMAIL_APP_PASSWORD in .env');
    return null;
  }

  return nodemailer.createTransport({
    service: 'gmail',
    host: 'smtp.gmail.com',
    port: 587,
    secure: false,
    auth: {
      user: process.env.GMAIL_USER,
      pass: process.env.GMAIL_APP_PASSWORD
    },
    tls: {
      rejectUnauthorized: false
    }
  });
};

// Send email (generic)
exports.sendEmail = async (options) => {
  const transporter = createTransporter();
  
  if (!transporter) {
    throw new Error('Email transporter not configured. Check your .env file.');
  }
  
  try {
    const mailOptions = {
      from: `"KChat App" <${process.env.GMAIL_USER}>`,
      to: options.to,
      subject: options.subject,
      html: options.html || options.message,
      text: options.text || options.message
    };

    const info = await transporter.sendMail(mailOptions);
    console.log(`✅ Email sent successfully to ${options.to}`);
    console.log(`📧 Message ID: ${info.messageId}`);
    
    return {
      success: true,
      messageId: info.messageId
    };
  } catch (error) {
    console.error('❌ Email send error:', error.message);
    throw new Error(`Failed to send email: ${error.message}`);
  }
};

// ✅ ORIGINAL: Send verification email (link method)
exports.sendVerificationEmail = async (email, username, verifyUrl) => {
  const html = `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Verify Your Email - KChat</title>
      <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; background: #f4f4f4; }
        .container { max-width: 600px; margin: 20px auto; background: #ffffff; border-radius: 10px; overflow: hidden; box-shadow: 0 4px 20px rgba(0,0,0,0.1); }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 40px 20px; text-align: center; }
        .header h1 { margin: 0; font-size: 28px; }
        .content { padding: 40px 30px; }
        .content h2 { color: #333; margin-top: 0; }
        .button { display: inline-block; padding: 15px 40px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; text-decoration: none; border-radius: 50px; margin: 25px 0; font-weight: bold; font-size: 16px; transition: transform 0.3s; }
        .button:hover { transform: translateY(-2px); box-shadow: 0 5px 20px rgba(102, 126, 234, 0.4); }
        .link-box { background: #f8f9fa; padding: 15px; border-radius: 8px; word-break: break-all; margin: 20px 0; border-left: 4px solid #667eea; font-family: monospace; font-size: 14px; color: #555; }
        .footer { text-align: center; padding: 30px; background: #f8f9fa; color: #666; font-size: 12px; border-top: 1px solid #e9ecef; }
        .warning { color: #856404; background: #fff3cd; padding: 12px; border-radius: 5px; margin: 20px 0; border-left: 4px solid #ffc107; }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <h1>🚀 Welcome to KChat!</h1>
        </div>
        <div class="content">
          <h2>Hi ${username},</h2>
          <p>Thank you for joining KChat! We're excited to have you on board. Please verify your email address to activate your account and start chatting.</p>
          
          <div style="text-align: center;">
            <a href="${verifyUrl}" class="button">Verify Email Address</a>
          </div>
          
          <div class="warning">
            <strong>⏰ This link expires in 24 hours.</strong>
          </div>
          
          <p>Or copy and paste this link into your browser:</p>
          <div class="link-box">${verifyUrl}</div>
          
          <p style="color: #666; font-size: 14px;">If you didn't create this account, you can safely ignore this email. No account will be activated.</p>
        </div>
        <div class="footer">
          <p>&copy; 2024 KChat. All rights reserved.</p>
          <p>🔒 Secure Messaging Platform</p>
        </div>
      </div>
    </body>
    </html>
  `;

  return await exports.sendEmail({
    to: email,
    subject: '✅ Verify Your Email Address - KChat',
    html: html,
    text: `Hi ${username}, Please verify your email by clicking: ${verifyUrl} (expires in 24 hours)`
  });
};

// ✅ NEW: Send OTP Email (code method)
exports.sendOTPEmail = async (email, username, otp, type = 'verification') => {
  const isVerification = type === 'verification';
  const title = isVerification ? 'Email Verification' : 'Password Reset';
  const color1 = isVerification ? '#667eea' : '#ff6b6b';
  const color2 = isVerification ? '#764ba2' : '#ee5a6f';
  const action = isVerification ? 'verify your email' : 'reset your password';
  
  const html = `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>${title} - KChat</title>
      <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f4f4f4; margin: 0; padding: 0; }
        .container { max-width: 600px; margin: 20px auto; background: #ffffff; border-radius: 15px; overflow: hidden; box-shadow: 0 4px 25px rgba(0,0,0,0.1); }
        .header { background: linear-gradient(135deg, ${color1} 0%, ${color2} 100%); color: white; padding: 40px 20px; text-align: center; }
        .header h1 { margin: 0; font-size: 28px; }
        .content { padding: 40px 30px; text-align: center; }
        .otp-box { background: #f8f9fa; border: 3px dashed ${color1}; border-radius: 10px; padding: 30px; margin: 30px 0; display: inline-block; }
        .otp-code { font-size: 48px; font-weight: bold; color: ${color1}; letter-spacing: 10px; font-family: 'Courier New', monospace; }
        .warning { color: #856404; background: #fff3cd; padding: 15px; border-radius: 8px; margin: 20px 0; font-size: 14px; }
        .footer { text-align: center; padding: 30px; background: #f8f9fa; color: #666; font-size: 12px; }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <h1>${isVerification ? '🔐' : '🔑'} ${title}</h1>
        </div>
        <div class="content">
          <h2>Hi ${username},</h2>
          <p>Use the code below to ${action}:</p>
          
          <div class="otp-box">
            <div class="otp-code">${otp}</div>
          </div>
          
          <div class="warning">
            ⏰ This code expires in <strong>10 minutes</strong><br>
            🔒 Do not share this code with anyone
          </div>
          
          <p style="color: #666; font-size: 14px;">
            If you didn't request this, you can safely ignore this email.
          </p>
        </div>
        <div class="footer">
          <p>&copy; 2024 KChat. Secure Messaging Platform</p>
        </div>
      </div>
    </body>
    </html>
  `;

  const text = `
    Hi ${username},
    
    Your ${type} code is: ${otp}
    
    This code expires in 10 minutes.
    Do not share this code with anyone.
    
    If you didn't request this, ignore this email.
    
    KChat Team
  `;

  return await exports.sendEmail({
    to: email,
    subject: `${isVerification ? '🔐' : '🔑'} Your ${title} Code - KChat`,
    html: html,
    text: text
  });
};

// ✅ ORIGINAL: Send password reset email (link method)
exports.sendPasswordResetEmail = async (email, username, resetUrl) => {
  const html = `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <title>Password Reset - KChat</title>
      <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; background: #f4f4f4; }
        .container { max-width: 600px; margin: 20px auto; background: #ffffff; border-radius: 10px; overflow: hidden; box-shadow: 0 4px 20px rgba(0,0,0,0.1); }
        .header { background: linear-gradient(135deg, #ff6b6b 0%, #ee5a6f 100%); color: white; padding: 40px 20px; text-align: center; }
        .content { padding: 40px 30px; }
        .button { display: inline-block; padding: 15px 40px; background: linear-gradient(135deg, #ff6b6b 0%, #ee5a6f 100%); color: white; text-decoration: none; border-radius: 50px; margin: 25px 0; font-weight: bold; }
        .warning { color: #721c24; background: #f8d7da; padding: 12px; border-radius: 5px; margin: 20px 0; border-left: 4px solid #dc3545; }
        .footer { text-align: center; padding: 30px; background: #f8f9fa; color: #666; font-size: 12px; }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <h1>🔐 Password Reset Request</h1>
        </div>
        <div class="content">
          <h2>Hi ${username},</h2>
          <p>We received a request to reset your KChat account password.</p>
          
          <div style="text-align: center;">
            <a href="${resetUrl}" class="button">Reset Password</a>
          </div>
          
          <div class="warning">
            <strong>⏰ This link expires in 10 minutes for security reasons.</strong>
          </div>
          
          <p style="color: #666;">If you didn't request this password reset, please ignore this email or contact support if you're concerned.</p>
        </div>
        <div class="footer">
          <p>&copy; 2024 KChat. All rights reserved.</p>
        </div>
      </div>
    </body>
    </html>
  `;

  return await exports.sendEmail({
    to: email,
    subject: '🔐 Password Reset Request - KChat',
    html: html,
    text: `Hi ${username}, Reset password: ${resetUrl} (expires in 10 minutes)`
  });
};

// Test connection on startup
exports.testConnection = async () => {
  const transporter = createTransporter();
  if (!transporter) {
    console.log('⚠️  Email service not configured. Emails will fail.');
    return false;
  }
  
  try {
    await transporter.verify();
    console.log('✅ Gmail SMTP connection verified successfully');
    return true;
  } catch (error) {
    console.error('❌ Gmail SMTP connection failed:', error.message);
    console.log('💡 Tip: Make sure you\'re using an App Password, not your regular Gmail password');
    return false;
  }
};