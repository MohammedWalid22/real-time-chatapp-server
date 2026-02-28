const express = require('express');
const router = express.Router();
const friendController = require('../controllers/friend.controller');
const { authMiddleware } = require('../middleware/auth.middleware');

router.get('/search', authMiddleware, friendController.searchUsers);
router.post('/request', authMiddleware, friendController.sendRequest);
router.get('/requests/incoming', authMiddleware, friendController.getIncomingRequests);
router.get('/requests/sent', authMiddleware, friendController.getSentRequests);
router.post('/accept', authMiddleware, friendController.acceptRequest);
router.post('/reject', authMiddleware, friendController.rejectRequest);
router.post('/cancel', authMiddleware, friendController.cancelRequest);
router.delete('/:userId', authMiddleware, friendController.removeFriend);
router.get('/', authMiddleware, friendController.getFriends);

module.exports = router;