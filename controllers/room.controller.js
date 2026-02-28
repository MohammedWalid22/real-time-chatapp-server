const Room = require('../models/Room');
const User = require('../models/User');
const Message = require('../models/Message');
const logger = require('../utils/logger');
const crypto = require('crypto');

// Get all rooms for current user
exports.getMyRooms = async (req, res, next) => {
  try {
    const rooms = await Room.find({
      'participants.user': req.user.id,
      isArchived: false
    })
    .populate('participants.user', 'username avatar status')
    .populate('lastMessage')
    .sort({ updatedAt: -1 });

    // Add unread count for each room
    const roomsWithUnread = await Promise.all(rooms.map(async (room) => {
      const unreadCount = await Message.countDocuments({
        room: room._id,
        'readBy.user': { $ne: req.user.id },
        sender: { $ne: req.user.id }
      });

      return {
        ...room.toObject(),
        unreadCount
      };
    }));

    res.json(roomsWithUnread);
  } catch (error) {
    next(error);
  }
};

// Create private room (1-on-1 chat)
exports.createPrivateRoom = async (req, res, next) => {
  try {
    const { userId } = req.body;

    if (userId === req.user.id) {
      return res.status(400).json({ message: 'Cannot create chat with yourself' });
    }

    // Check if room already exists
    const existingRoom = await Room.findOne({
      type: 'private',
      participants: {
        $all: [
          { $elemMatch: { user: req.user.id } },
          { $elemMatch: { user: userId } }
        ]
      }
    }).populate('participants.user', 'username avatar status');

    if (existingRoom) {
      return res.json(existingRoom);
    }

    // Generate encryption key for E2EE
    const encryptionKey = crypto.randomBytes(32).toString('hex');

    const room = await Room.create({
      type: 'private',
      name: 'Private Chat',
      owner: req.user.id,
      participants: [
        { user: req.user.id, role: 'admin' },
        { user: userId, role: 'admin' }
      ],
      isEncrypted: true,
      encryptionKey
    });

    const populatedRoom = await Room.findById(room._id)
      .populate('participants.user', 'username avatar status');

    res.status(201).json(populatedRoom);
  } catch (error) {
    next(error);
  }
};

// Create group
exports.createGroup = async (req, res, next) => {
  try {
    const { name, description, participants, avatar } = req.body;

    if (!name || name.length < 3) {
      return res.status(400).json({ message: 'Group name must be at least 3 characters' });
    }

    if (!participants || participants.length < 2) {
      return res.status(400).json({ message: 'Group must have at least 2 other participants' });
    }

    // Add creator to participants
    const allParticipants = [
      { user: req.user.id, role: 'admin' },
      ...participants.map(id => ({ user: id, role: 'member' }))
    ];

    const room = await Room.create({
      type: 'group',
      name,
      description,
      avatar,
      owner: req.user.id,
      participants: allParticipants,
      settings: {
        onlyAdminsCanPost: false,
        onlyAdminsCanAddMembers: true,
        isPublic: false
      }
    });

    const populatedRoom = await Room.findById(room._id)
      .populate('participants.user', 'username avatar status');

    // Notify participants
    const io = req.app.get('io');
    participants.forEach(userId => {
      io.to(userId.toString()).emit('added-to-group', {
        room: populatedRoom,
        addedBy: req.user.id
      });
    });

    res.status(201).json(populatedRoom);
  } catch (error) {
    next(error);
  }
};

// Get single room
exports.getRoom = async (req, res, next) => {
  try {
    const room = await Room.findById(req.params.id)
      .populate('participants.user', 'username avatar status lastSeen');

    if (!room) {
      return res.status(404).json({ message: 'Room not found' });
    }

    // Check if user is participant
    const isParticipant = room.participants.some(
      p => p.user._id.toString() === req.user.id
    );

    if (!isParticipant) {
      return res.status(403).json({ message: 'Not authorized to access this room' });
    }

    res.json(room);
  } catch (error) {
    next(error);
  }
};

// Update room
exports.updateRoom = async (req, res, next) => {
  try {
    const { name, description, avatar, settings } = req.body;
    const room = await Room.findById(req.params.id);

    if (!room) {
      return res.status(404).json({ message: 'Room not found' });
    }

    // Check if user is admin
    const isAdmin = room.participants.some(
      p => p.user.toString() === req.user.id && ['admin', 'moderator'].includes(p.role)
    );

    if (!isAdmin) {
      return res.status(403).json({ message: 'Only admins can update room' });
    }

    const updates = {};
    if (name) updates.name = name;
    if (description !== undefined) updates.description = description;
    if (avatar) updates.avatar = avatar;
    if (settings) updates.settings = { ...room.settings, ...settings };

    const updatedRoom = await Room.findByIdAndUpdate(
      req.params.id,
      updates,
      { new: true }
    ).populate('participants.user', 'username avatar status');

    // Notify participants
    const io = req.app.get('io');
    room.participants.forEach(p => {
      io.to(p.user.toString()).emit('room-updated', updatedRoom);
    });

    res.json(updatedRoom);
  } catch (error) {
    next(error);
  }
};

// Delete room
exports.deleteRoom = async (req, res, next) => {
  try {
    const room = await Room.findById(req.params.id);

    if (!room) {
      return res.status(404).json({ message: 'Room not found' });
    }

    // Only owner can delete
    if (room.owner.toString() !== req.user.id) {
      return res.status(403).json({ message: 'Only owner can delete room' });
    }

    // Soft delete - archive instead
    room.isArchived = true;
    room.archivedAt = new Date();
    await room.save();

    // Notify participants
    const io = req.app.get('io');
    room.participants.forEach(p => {
      io.to(p.user.toString()).emit('room-deleted', { roomId: room._id });
    });

    res.json({ message: 'Room deleted successfully' });
  } catch (error) {
    next(error);
  }
};

// Add member
exports.addMember = async (req, res, next) => {
  try {
    const { userId } = req.body;
    const room = await Room.findById(req.params.id);

    if (!room) {
      return res.status(404).json({ message: 'Room not found' });
    }

    // Check permissions
    const canAdd = room.settings.onlyAdminsCanAddMembers
      ? room.participants.some(p => p.user.toString() === req.user.id && p.role === 'admin')
      : room.participants.some(p => p.user.toString() === req.user.id);

    if (!canAdd) {
      return res.status(403).json({ message: 'Not authorized to add members' });
    }

    // Check if already member
    const isMember = room.participants.some(p => p.user.toString() === userId);
    if (isMember) {
      return res.status(400).json({ message: 'User is already a member' });
    }

    room.participants.push({ user: userId, role: 'member' });
    await room.save();

    const updatedRoom = await Room.findById(room._id)
      .populate('participants.user', 'username avatar status');

    // Notify new member
    const io = req.app.get('io');
    io.to(userId).emit('added-to-group', {
      room: updatedRoom,
      addedBy: req.user.id
    });

    res.json(updatedRoom);
  } catch (error) {
    next(error);
  }
};

// Remove member
exports.removeMember = async (req, res, next) => {
  try {
    const { userId } = req.params;
    const room = await Room.findById(req.params.id);

    if (!room) {
      return res.status(404).json({ message: 'Room not found' });
    }

    // Cannot remove owner
    if (userId === room.owner.toString()) {
      return res.status(400).json({ message: 'Cannot remove owner' });
    }

    // Check permissions (admin or self-removal)
    const isAdmin = room.participants.some(
      p => p.user.toString() === req.user.id && p.role === 'admin'
    );
    const isSelf = userId === req.user.id;

    if (!isAdmin && !isSelf) {
      return res.status(403).json({ message: 'Not authorized' });
    }

    room.participants = room.participants.filter(
      p => p.user.toString() !== userId
    );
    await room.save();

    // Notify removed user
    const io = req.app.get('io');
    io.to(userId).emit('removed-from-group', {
      roomId: room._id,
      removedBy: req.user.id
    });

    res.json({ message: 'Member removed successfully' });
  } catch (error) {
    next(error);
  }
};

// Update member role
exports.updateMemberRole = async (req, res, next) => {
  try {
    const { userId } = req.params;
    const { role } = req.body;
    const room = await Room.findById(req.params.id);

    if (!room) {
      return res.status(404).json({ message: 'Room not found' });
    }

    // Only owner can change roles
    if (room.owner.toString() !== req.user.id) {
      return res.status(403).json({ message: 'Only owner can change roles' });
    }

    const participant = room.participants.find(
      p => p.user.toString() === userId
    );

    if (!participant) {
      return res.status(404).json({ message: 'Member not found' });
    }

    participant.role = role;
    await room.save();

    res.json({ message: 'Role updated successfully' });
  } catch (error) {
    next(error);
  }
};

// Join room (for public groups)
exports.joinRoom = async (req, res, next) => {
  try {
    const room = await Room.findById(req.params.id);

    if (!room) {
      return res.status(404).json({ message: 'Room not found' });
    }

    if (!room.settings.isPublic) {
      return res.status(403).json({ message: 'This is a private group' });
    }

    const isMember = room.participants.some(
      p => p.user.toString() === req.user.id
    );

    if (isMember) {
      return res.status(400).json({ message: 'Already a member' });
    }

    if (room.settings.joinApprovalRequired) {
      // Send join request
      return res.json({ message: 'Join request sent, waiting for approval' });
    }

    room.participants.push({ user: req.user.id, role: 'member' });
    await room.save();

    const updatedRoom = await Room.findById(room._id)
      .populate('participants.user', 'username avatar status');

    res.json(updatedRoom);
  } catch (error) {
    next(error);
  }
};

// Leave room
exports.leaveRoom = async (req, res, next) => {
  try {
    const room = await Room.findById(req.params.id);

    if (!room) {
      return res.status(404).json({ message: 'Room not found' });
    }

    // Owner cannot leave, must delete or transfer ownership
    if (room.owner.toString() === req.user.id) {
      return res.status(400).json({ 
        message: 'Owner cannot leave. Transfer ownership or delete the group' 
      });
    }

    room.participants = room.participants.filter(
      p => p.user.toString() !== req.user.id
    );
    await room.save();

    res.json({ message: 'Left room successfully' });
  } catch (error) {
    next(error);
  }
};

// Generate invite link
exports.generateInviteLink = async (req, res, next) => {
  try {
    const room = await Room.findById(req.params.id);

    if (!room) {
      return res.status(404).json({ message: 'Room not found' });
    }

    const isAdmin = room.participants.some(
      p => p.user.toString() === req.user.id && p.role === 'admin'
    );

    if (!isAdmin) {
      return res.status(403).json({ message: 'Only admins can generate invite links' });
    }

    const inviteCode = crypto.randomBytes(16).toString('hex');
    
    room.inviteLink = {
      code: inviteCode,
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
      maxUses: 100,
      uses: 0
    };
    
    await room.save();

    res.json({
      inviteLink: `${process.env.CLIENT_URL}/join/${inviteCode}`,
      expiresAt: room.inviteLink.expiresAt
    });
  } catch (error) {
    next(error);
  }
};

// Join by invite
exports.joinByInvite = async (req, res, next) => {
  try {
    const { code } = req.body;
    
    const room = await Room.findOne({ 'inviteLink.code': code });

    if (!room) {
      return res.status(404).json({ message: 'Invalid invite link' });
    }

    // Check expiration
    if (room.inviteLink.expiresAt < Date.now()) {
      return res.status(400).json({ message: 'Invite link expired' });
    }

    // Check max uses
    if (room.inviteLink.uses >= room.inviteLink.maxUses) {
      return res.status(400).json({ message: 'Invite link max uses reached' });
    }

    // Check if already member
    const isMember = room.participants.some(
      p => p.user.toString() === req.user.id
    );

    if (isMember) {
      return res.status(400).json({ message: 'Already a member' });
    }

    room.participants.push({ user: req.user.id, role: 'member' });
    room.inviteLink.uses += 1;
    await room.save();

    const updatedRoom = await Room.findById(room._id)
      .populate('participants.user', 'username avatar status');

    res.json(updatedRoom);
  } catch (error) {
    next(error);
  }
};