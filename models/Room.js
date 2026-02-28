const mongoose = require('mongoose');

const roomSchema = new mongoose.Schema({
  name: {
    type: String,
    trim: true,
    maxlength: [100, 'Room name cannot exceed 100 characters']
  },
  type: {
    type: String,
    enum: ['private', 'group', 'channel'],
    default: 'private'
  },
  description: {
    type: String,
    maxlength: [500, 'Description cannot exceed 500 characters']
  },
  avatar: {
    type: String,
    default: ''
  },
  owner: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  participants: [{
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    role: {
      type: String,
      enum: ['admin', 'moderator', 'member'],
      default: 'member'
    },
    joinedAt: {
      type: Date,
      default: Date.now
    },
    lastRead: {
      type: Date,
      default: Date.now
    },
    isMuted: {
      type: Boolean,
      default: false
    },
    muteDuration: Date
  }],
  // For private chats
  isEncrypted: {
    type: Boolean,
    default: true
  },
  encryptionKey: {
    type: String,
    default: null
    // Removed select: false so it comes with queries by default
  },
  // Group settings
  settings: {
    onlyAdminsCanPost: {
      type: Boolean,
      default: false
    },
    onlyAdminsCanAddMembers: {
      type: Boolean,
      default: true
    },
    isPublic: {
      type: Boolean,
      default: false
    },
    joinApprovalRequired: {
      type: Boolean,
      default: false
    }
  },
  // Invite link
  inviteLink: {
    code: String,
    expiresAt: Date,
    maxUses: Number,
    uses: {
      type: Number,
      default: 0
    }
  },
  lastMessage: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Message'
  },
  unreadCounts: [{
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    count: {
      type: Number,
      default: 0
    }
  }],
  isArchived: {
    type: Boolean,
    default: false
  },
  archivedAt: Date
}, {
  timestamps: true
});

// Indexes
roomSchema.index({ participants: 1 });
roomSchema.index({ type: 1 });
roomSchema.index({ 'inviteLink.code': 1 });

// Pre-save middleware to generate encryption key for private chats
roomSchema.pre('save', async function(next) {
  if (this.isNew && this.type === 'private' && this.isEncrypted && !this.encryptionKey) {
    const crypto = require('crypto');
    this.encryptionKey = crypto.randomBytes(32).toString('hex');
  }
  next();
});

// Method to ensure encryption key exists
roomSchema.methods.ensureEncryptionKey = async function() {
  if (this.type === 'private' && this.isEncrypted && !this.encryptionKey) {
    const crypto = require('crypto');
    this.encryptionKey = crypto.randomBytes(32).toString('hex');
    await this.save();
  }
  return this.encryptionKey;
};

module.exports = mongoose.model('Room', roomSchema);