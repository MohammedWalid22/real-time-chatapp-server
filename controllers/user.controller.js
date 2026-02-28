const User = require('../models/User');
const logger = require('../utils/logger');

exports.getMe = async (req, res, next) => {
  try {
    const user = await User.findById(req.user.id)
      .populate('friends.user', 'username avatar status');
    
    res.json({
      id: user._id,
      username: user.username,
      email: user.email,
      avatar: user.avatar,
      status: user.status,
      lastSeen: user.lastSeen,
      isEmailVerified: user.isEmailVerified,
      twoFactorEnabled: user.twoFactorEnabled,
      privacySettings: user.privacySettings,
      friends: user.friends,
      createdAt: user.createdAt
    });
  } catch (error) {
    next(error);
  }
};

exports.updateMe = async (req, res, next) => {
  try {
    const allowedFields = ['username', 'bio', 'privacySettings'];
    const updates = {};
    
    Object.keys(req.body).forEach(key => {
      if (allowedFields.includes(key)) {
        updates[key] = req.body[key];
      }
    });
    
    const user = await User.findByIdAndUpdate(
      req.user.id,
      updates,
      { new: true, runValidators: true }
    );
    
    res.json(user);
  } catch (error) {
    next(error);
  }
};

exports.updatePassword = async (req, res, next) => {
  try {
    const { currentPassword, newPassword } = req.body;
    
    const user = await User.findById(req.user.id).select('+password');
    
    if (!(await user.comparePassword(currentPassword))) {
      return res.status(401).json({ message: 'Current password is incorrect' });
    }
    
    user.password = newPassword;
    await user.save();
    
    logger.info(`Password changed for user: ${user.email}`);
    
    res.json({ message: 'Password updated successfully' });
  } catch (error) {
    next(error);
  }
};

exports.uploadAvatar = async (req, res, next) => {
  try {
    if (!req.file) {
      return res.status(400).json({ message: 'No file uploaded' });
    }
    
    // Process image with sharp
    const sharp = require('sharp');
    const filename = `avatar-${req.user.id}-${Date.now()}.jpeg`;
    
    await sharp(req.file.buffer)
      .resize(500, 500)
      .jpeg({ quality: 90 })
      .toFile(`uploads/${filename}`);
    
    const user = await User.findByIdAndUpdate(
      req.user.id,
      { avatar: `/uploads/${filename}` },
      { new: true }
    );
    
    res.json({ avatar: user.avatar });
  } catch (error) {
    next(error);
  }
};

exports.deleteMe = async (req, res, next) => {
  try {
    await User.findByIdAndUpdate(req.user.id, { isActive: false });
    
    logger.info(`User account deactivated: ${req.user.email}`);
    
    res.json({ message: 'Account deactivated successfully' });
  } catch (error) {
    next(error);
  }
};

exports.searchUsers = async (req, res, next) => {
  try {
    const { q } = req.query;
    
    if (!q || q.length < 2) {
      return res.json([]);
    }
    
    const users = await User.find({
      $or: [
        { username: { $regex: q, $options: 'i' } },
        { email: { $regex: q, $options: 'i' } }
      ],
      _id: { $ne: req.user.id },
      isBanned: false
    })
    .select('username avatar status')
    .limit(20);
    
    res.json(users);
  } catch (error) {
    next(error);
  }
};

exports.getUser = async (req, res, next) => {
  try {
    const user = await User.findById(req.params.id)
      .select('username avatar status lastSeen createdAt');
    
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    // Check privacy settings
    const isFriend = req.user.friends.some(f => f.user.toString() === req.params.id);
    
    let response = {
      id: user._id,
      username: user.username,
      avatar: user.avatar
    };
    
    // Only show status if privacy allows
    const privacy = user.privacySettings;
    if (privacy.lastSeenVisibility === 'everyone' || 
        (privacy.lastSeenVisibility === 'contacts' && isFriend)) {
      response.status = user.status;
      response.lastSeen = user.lastSeen;
    }
    
    res.json(response);
  } catch (error) {
    next(error);
  }
};