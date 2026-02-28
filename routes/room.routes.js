const express = require('express');
const router = express.Router();
const roomController = require('../controllers/room.controller');
const { authMiddleware } = require('../middleware/auth.middleware');

router.get('/', authMiddleware, roomController.getMyRooms);
router.post('/private', authMiddleware, roomController.createPrivateRoom);
router.post('/group', authMiddleware, roomController.createGroup);
router.get('/:id', authMiddleware, roomController.getRoom);
router.patch('/:id', authMiddleware, roomController.updateRoom);
router.delete('/:id', authMiddleware, roomController.deleteRoom);

// Members
router.post('/:id/members', authMiddleware, roomController.addMember);
router.delete('/:id/members/:userId', authMiddleware, roomController.removeMember);
router.patch('/:id/members/:userId/role', authMiddleware, roomController.updateMemberRole);

// Join/Leave
router.post('/:id/join', authMiddleware, roomController.joinRoom);
router.post('/:id/leave', authMiddleware, roomController.leaveRoom);

// Invite link
router.post('/:id/invite', authMiddleware, roomController.generateInviteLink);
router.post('/join-by-invite', authMiddleware, roomController.joinByInvite);

module.exports = router;