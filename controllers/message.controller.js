const Message = require('../models/Message');
const Room = require('../models/Room');
const User = require('../models/User');
const { encryptMessage, decryptMessage, generateEncryptionKey } = require('../services/encryption.service');
const logger = require('../utils/logger');

// Get messages for a room
exports.getMessages = async (req, res, next) => {
  try {
    const { roomId } = req.params;
    const { page = 1, limit = 50 } = req.query;

    // Check if user is in room
    const room = await Room.findById(roomId);
    if (!room) {
      return res.status(404).json({ message: 'Room not found' });
    }

    const isParticipant = room.participants.some(
      p => p.user.toString() === req.user.id
    );

    if (!isParticipant) {
      return res.status(403).json({ message: 'Not authorized' });
    }

    const messages = await Message.find({ 
      room: roomId,
      isDeleted: false
    })
    .populate('sender', 'username avatar')
    .populate('replyTo', 'content sender')
    .sort({ createdAt: -1 })
    .limit(limit * 1)
    .skip((page - 1) * limit);

    // Decrypt messages if encrypted
    const decryptedMessages = messages.map(msg => {
      const obj = msg.toObject();
      if (msg.metadata?.encrypted && room.encryptionKey) {
        try {
          obj.content = decryptMessage(msg.content, room.encryptionKey);
        } catch (e) {
          logger.error('Decrypt error:', e.message);
          obj.content = '[Encrypted message]';
        }
      }
      return obj;
    });

    res.json(decryptedMessages.reverse());
  } catch (error) {
    next(error);
  }
};

// Send message
exports.sendMessage = async (req, res, next) => {
  try {
    const { roomId, content, type = 'text', replyTo } = req.body;

    // Validate
    if (!content || content.trim().length === 0) {
      return res.status(400).json({ message: 'Message content required' });
    }

    if (content.length > 5000) {
      return res.status(400).json({ message: 'Message too long (max 5000 chars)' });
    }

    // Check room and membership
    const room = await Room.findById(roomId);
    if (!room) {
      return res.status(404).json({ message: 'Room not found' });
    }

    const participant = room.participants.find(
      p => p.user.toString() === req.user.id
    );

    if (!participant) {
      return res.status(403).json({ message: 'Not a member of this room' });
    }

    // Check if only admins can post
    if (room.settings?.onlyAdminsCanPost && participant.role !== 'admin') {
      return res.status(403).json({ message: 'Only admins can post' });
    }

    // Ensure room has encryption key if it's private and encrypted
    if (room.type === 'private' && room.isEncrypted && !room.encryptionKey) {
      room.encryptionKey = generateEncryptionKey();
      await room.save();
    }

    // Encrypt content for private rooms
    let messageContent = content;
    let isEncrypted = false;

    if (room.type === 'private' && room.isEncrypted && room.encryptionKey) {
      messageContent = encryptMessage(content, room.encryptionKey);
      isEncrypted = true;
    }

    const message = await Message.create({
      room: roomId,
      sender: req.user.id,
      content: messageContent,
      type,
      replyTo,
      metadata: {
        encrypted: isEncrypted,
        algorithm: isEncrypted ? 'AES-256-CBC' : 'none'
      }
    });

    await message.populate('sender', 'username avatar');

    // Update room's last message
    room.lastMessage = message._id;
    await room.save();

    // Update unread counts for other participants
    for (const p of room.participants) {
      if (p.user.toString() !== req.user.id) {
        const unreadIndex = room.unreadCounts?.findIndex(
          u => u.user.toString() === p.user.toString()
        );
        
        if (unreadIndex >= 0) {
          room.unreadCounts[unreadIndex].count += 1;
        } else {
          if (!room.unreadCounts) room.unreadCounts = [];
          room.unreadCounts.push({ user: p.user, count: 1 });
        }
      }
    }
    await room.save();

    // Emit to room via socket
    const io = req.app.get('io');
    const messageToSend = {
      ...message.toObject(),
      content: content // Send original to clients
    };
    
    io.to(roomId).emit('new-message', messageToSend);

    res.status(201).json(message);
  } catch (error) {
    next(error);
  }
};

// Edit message
exports.editMessage = async (req, res, next) => {
  try {
    const { id } = req.params;
    const { content } = req.body;

    const message = await Message.findById(id);

    if (!message) {
      return res.status(404).json({ message: 'Message not found' });
    }

    // Only sender can edit
    if (message.sender.toString() !== req.user.id) {
      return res.status(403).json({ message: 'Can only edit your own messages' });
    }

    // Can only edit within 15 minutes
    const fifteenMinutes = 15 * 60 * 1000;
    if (Date.now() - message.createdAt > fifteenMinutes) {
      return res.status(400).json({ message: 'Can only edit within 15 minutes' });
    }

    // Save edit history
    if (!message.editHistory) message.editHistory = [];
    message.editHistory.push({
      content: message.content,
      editedAt: new Date()
    });

    // Encrypt new content if needed
    const room = await Room.findById(message.room);
    
    // Ensure encryption key exists
    if (room.type === 'private' && room.isEncrypted && !room.encryptionKey) {
      room.encryptionKey = generateEncryptionKey();
      await room.save();
    }
    
    if (room.type === 'private' && room.isEncrypted && room.encryptionKey) {
      message.content = encryptMessage(content, room.encryptionKey);
      message.metadata = { ...message.metadata, encrypted: true, algorithm: 'AES-256-CBC' };
    } else {
      message.content = content;
      message.metadata = { ...message.metadata, encrypted: false, algorithm: 'none' };
    }

    message.isEdited = true;
    await message.save();

    await message.populate('sender', 'username avatar');

    // Notify room
    const io = req.app.get('io');
    io.to(message.room.toString()).emit('message-edited', {
      ...message.toObject(),
      content
    });

    res.json(message);
  } catch (error) {
    next(error);
  }
};

// Delete message (soft delete)
exports.deleteMessage = async (req, res, next) => {
  try {
    const { id } = req.params;

    const message = await Message.findById(id);

    if (!message) {
      return res.status(404).json({ message: 'Message not found' });
    }

    // Check permissions (sender or admin)
    const room = await Room.findById(message.room);
    const isSender = message.sender.toString() === req.user.id;
    const isAdmin = room.participants.some(
      p => p.user.toString() === req.user.id && p.role === 'admin'
    );

    if (!isSender && !isAdmin) {
      return res.status(403).json({ message: 'Not authorized' });
    }

    message.isDeleted = true;
    message.deletedAt = new Date();
    message.deletedBy = req.user.id;
    message.content = '[Message deleted]';
    await message.save();

    // Notify room
    const io = req.app.get('io');
    io.to(message.room.toString()).emit('message-deleted', {
      messageId: message._id,
      deletedBy: req.user.id
    });

    res.json({ message: 'Message deleted' });
  } catch (error) {
    next(error);
  }
};

// Add reaction
exports.addReaction = async (req, res, next) => {
  try {
    const { id } = req.params;
    const { emoji } = req.body;

    const message = await Message.findById(id);

    if (!message) {
      return res.status(404).json({ message: 'Message not found' });
    }

    // Check if user already reacted with this emoji
    const existingReaction = message.reactions?.find(
      r => r.user.toString() === req.user.id && r.emoji === emoji
    );

    if (existingReaction) {
      // Remove reaction (toggle)
      message.reactions = message.reactions.filter(
        r => !(r.user.toString() === req.user.id && r.emoji === emoji)
      );
    } else {
      // Add reaction
      if (!message.reactions) message.reactions = [];
      message.reactions.push({
        emoji,
        user: req.user.id
      });
    }

    await message.save();

    // Notify room
    const io = req.app.get('io');
    io.to(message.room.toString()).emit('message-reaction', {
      messageId: message._id,
      reactions: message.reactions
    });

    res.json(message);
  } catch (error) {
    next(error);
  }
};

// Mark as read
exports.markAsRead = async (req, res, next) => {
  try {
    const { id } = req.params;

    const message = await Message.findById(id);

    if (!message) {
      return res.status(404).json({ message: 'Message not found' });
    }

    // Check if already read
    const alreadyRead = message.readBy?.some(
      r => r.user.toString() === req.user.id
    );

    if (!alreadyRead) {
      if (!message.readBy) message.readBy = [];
      message.readBy.push({
        user: req.user.id,
        readAt: new Date()
      });
      await message.save();

      // Update room unread count
      const room = await Room.findById(message.room);
      const unreadEntry = room.unreadCounts?.find(
        u => u.user.toString() === req.user.id
      );
      
      if (unreadEntry && unreadEntry.count > 0) {
        unreadEntry.count = Math.max(0, unreadEntry.count - 1);
        await room.save();
      }

      // Notify sender
      const io = req.app.get('io');
      io.to(message.sender.toString()).emit('message-read', {
        messageId: message._id,
        readBy: req.user.id,
        readAt: new Date()
      });
    }

    res.json({ message: 'Marked as read' });
  } catch (error) {
    next(error);
  }
};

// Search messages
exports.searchMessages = async (req, res, next) => {
  try {
    const { roomId, query } = req.query;

    if (!query || query.length < 2) {
      return res.status(400).json({ message: 'Search query too short' });
    }

    const room = await Room.findById(roomId);
    if (!room) {
      return res.status(404).json({ message: 'Room not found' });
    }

    const isParticipant = room.participants.some(
      p => p.user.toString() === req.user.id
    );

    if (!isParticipant) {
      return res.status(403).json({ message: 'Not authorized' });
    }

    const messages = await Message.find({
      room: roomId,
      isDeleted: false,
      $text: { $search: query }
    })
    .populate('sender', 'username avatar')
    .sort({ score: { $meta: 'textScore' } })
    .limit(50);

    // Decrypt messages for search results if encrypted
    const decryptedMessages = messages.map(msg => {
      const obj = msg.toObject();
      if (msg.metadata?.encrypted && room.encryptionKey) {
        try {
          obj.content = decryptMessage(msg.content, room.encryptionKey);
        } catch (e) {
          obj.content = '[Encrypted message]';
        }
      }
      return obj;
    });

    res.json(decryptedMessages);
  } catch (error) {
    next(error);
  }
};