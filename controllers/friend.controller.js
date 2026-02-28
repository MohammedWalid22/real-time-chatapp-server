const FriendRequest = require('../models/FriendRequest');
const User = require('../models/User');
const Room = require('../models/Room');
const logger = require('../utils/logger');

exports.searchUsers = async (req, res, next) => {
  try {
    const { q } = req.query;
    if (!q || q.length < 2) return res.json([]);

    const users = await User.find({
      $or: [
        { username: { $regex: q, $options: 'i' } },
        { email: { $regex: q, $options: 'i' } }
      ],
      _id: { $ne: req.user.id },
      isBanned: false
    }).select('username email avatar status');

    res.json(users);
  } catch (err) {
    next(err);
  }
};

exports.sendRequest = async (req, res, next) => {
  try {
    const { userId } = req.body;

    if (userId === req.user.id) {
      return res.status(400).json({ message: "Cannot add yourself" });
    }

    // Check if already friends
    const currentUser = await User.findById(req.user.id);
    const isAlreadyFriend = currentUser.friends.some(
      f => f.user.toString() === userId && f.status === 'accepted'
    );
    
    if (isAlreadyFriend) {
      return res.status(400).json({ message: 'Already friends' });
    }

    // Check for existing request
    const existingRequest = await FriendRequest.findOne({
      $or: [
        { sender: req.user.id, receiver: userId },
        { sender: userId, receiver: req.user.id }
      ],
      status: 'pending'
    });

    if (existingRequest) {
      return res.status(400).json({ message: 'Request already exists' });
    }

    const request = await FriendRequest.create({
      sender: req.user.id,
      receiver: userId
    });

    await request.populate('sender', 'username email avatar');

    // Emit to receiver via socket
    const io = req.app.get('io');
    io.to(userId).emit('new-friend-request', {
      requestId: request._id,
      sender: request.sender,
      createdAt: request.createdAt
    });

    res.status(201).json({ message: 'Request sent', request });
  } catch (err) {
    next(err);
  }
};

exports.getIncomingRequests = async (req, res, next) => {
  try {
    const requests = await FriendRequest.find({
      receiver: req.user.id,
      status: 'pending'
    }).populate('sender', 'username email avatar status');

    res.json(requests);
  } catch (err) {
    next(err);
  }
};

exports.getSentRequests = async (req, res, next) => {
  try {
    const requests = await FriendRequest.find({
      sender: req.user.id,
      status: 'pending'
    }).populate('receiver', 'username email avatar status');

    res.json(requests);
  } catch (err) {
    next(err);
  }
};

exports.acceptRequest = async (req, res, next) => {
  try {
    const { requestId } = req.body;

    const request = await FriendRequest.findById(requestId);
    if (!request) return res.status(404).json({ message: 'Request not found' });
    
    if (request.receiver.toString() !== req.user.id) {
      return res.status(403).json({ message: 'Not authorized' });
    }

    request.status = 'accepted';
    await request.save();

    // Add to friends lists
    await User.findByIdAndUpdate(request.sender, {
      $addToSet: { friends: { user: request.receiver, status: 'accepted' } }
    });
    await User.findByIdAndUpdate(request.receiver, {
      $addToSet: { friends: { user: request.sender, status: 'accepted' } }
    });

    // Create private room
    let room = await Room.findOne({
      type: 'private',
      participants: { 
        $all: [
          { $elemMatch: { user: request.sender } },
          { $elemMatch: { user: request.receiver } }
        ] 
      }
    });

    if (!room) {
      room = await Room.create({
        type: 'private',
        owner: req.user.id,
        name: 'Private Chat',
        participants: [
          { user: request.sender },
          { user: request.receiver }
        ]
      });
    }

    const fullRoom = await Room.findById(room._id)
      .populate('participants.user', 'username avatar status');

    // Notify both users
    const io = req.app.get('io');
    const eventData = {
      requestId: request._id,
      acceptedBy: req.user.id,
      room: fullRoom
    };

    io.to(request.sender.toString()).emit('friend-request-accepted', eventData);
    io.to(request.receiver.toString()).emit('friend-request-accepted', eventData);

    res.json({ message: 'Accepted', room: fullRoom });
  } catch (err) {
    next(err);
  }
};

exports.rejectRequest = async (req, res, next) => {
  try {
    const { requestId } = req.body;

    const request = await FriendRequest.findById(requestId);
    if (!request) return res.status(404).json({ message: 'Request not found' });
    
    if (request.receiver.toString() !== req.user.id) {
      return res.status(403).json({ message: 'Not authorized' });
    }

    request.status = 'rejected';
    await request.save();

    const io = req.app.get('io');
    io.to(request.sender.toString()).emit('friend-request-rejected', {
      requestId: request._id,
      rejectedBy: req.user.id
    });

    res.json({ message: 'Rejected' });
  } catch (err) {
    next(err);
  }
};

exports.cancelRequest = async (req, res, next) => {
  try {
    const { requestId } = req.body;

    const request = await FriendRequest.findById(requestId);
    if (!request) return res.status(404).json({ message: 'Request not found' });
    
    if (request.sender.toString() !== req.user.id) {
      return res.status(403).json({ message: 'Not authorized' });
    }

    await FriendRequest.findByIdAndDelete(requestId);

    const io = req.app.get('io');
    io.to(request.receiver.toString()).emit('friend-request-cancelled', {
      requestId: request._id
    });

    res.json({ message: 'Cancelled' });
  } catch (err) {
    next(err);
  }
};

exports.removeFriend = async (req, res, next) => {
  try {
    const { userId } = req.params;
    
    await User.findByIdAndUpdate(req.user.id, {
      $pull: { friends: { user: userId } }
    });
    
    await User.findByIdAndUpdate(userId, {
      $pull: { friends: { user: req.user.id } }
    });

    await FriendRequest.deleteMany({
      $or: [
        { sender: req.user.id, receiver: userId },
        { sender: userId, receiver: req.user.id }
      ]
    });

    res.json({ message: 'Friend removed' });
  } catch (err) {
    next(err);
  }
};

exports.getFriends = async (req, res, next) => {
  try {
    const user = await User.findById(req.user.id)
      .populate('friends.user', 'username email avatar status lastSeen');
    
    const acceptedFriends = user.friends.filter(f => f.status === 'accepted');
    
    res.json(acceptedFriends);
  } catch (err) {
    next(err);
  }
};