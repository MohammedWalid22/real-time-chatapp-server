const express = require('express');
const router = express.Router();
const { body } = require('express-validator');
const userController = require('../controllers/user.controller');
const { authMiddleware } = require('../middleware/auth.middleware');
const upload = require('../middleware/upload.middleware');

router.get('/me', authMiddleware, userController.getMe);
router.patch('/me', authMiddleware, userController.updateMe);
router.delete('/me', authMiddleware, userController.deleteMe);

router.patch('/password', authMiddleware, [
  body('currentPassword').notEmpty(),
  body('newPassword').isLength({ min: 8 })
], userController.updatePassword);

router.post('/avatar', authMiddleware, upload.single('avatar'), userController.uploadAvatar);

router.get('/search', authMiddleware, userController.searchUsers);
router.get('/:id', authMiddleware, userController.getUser);

module.exports = router;