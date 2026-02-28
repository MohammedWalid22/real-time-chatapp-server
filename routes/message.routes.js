const express = require('express');
const router = express.Router();
const messageController = require('../controllers/message.controller');
const { authMiddleware } = require('../middleware/auth.middleware');

router.get('/room/:roomId', authMiddleware, messageController.getMessages);
router.post('/', authMiddleware, messageController.sendMessage);
router.patch('/:id', authMiddleware, messageController.editMessage);
router.delete('/:id', authMiddleware, messageController.deleteMessage);
router.post('/:id/react', authMiddleware, messageController.addReaction);
router.post('/:id/read', authMiddleware, messageController.markAsRead);

// Search messages
router.get('/search', authMiddleware, messageController.searchMessages);

module.exports = router;