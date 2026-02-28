const mongoose = require('mongoose');

const messageSchema = new mongoose.Schema({
  room: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Room',
    required: true,
    index: true
  },
  sender: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  // Encrypted content
  content: {
    type: String,
    required: true
  },
  // For E2EE - encrypted for each recipient
  encryptedContent: [{
    recipient: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    encryptedKey: String, // Encrypted AES key for this recipient
    encryptedData: String // The actual encrypted message
  }],
  type: {
    type: String,
    enum: ['text', 'image', 'video', 'audio', 'file', 'voice', 'location', 'contact'],
    default: 'text'
  },
  metadata: {
    fileName: String,
    fileSize: Number,
    mimeType: String,
    duration: Number, // For voice/video
    dimensions: {
      width: Number,
      height: Number
    },
    encrypted: {
      type: Boolean,
      default: false
    },
    algorithm: {
      type: String,
      default: 'none'
    }
  },
  replyTo: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Message',
    default: null
  },
  reactions: [{
    emoji: String,
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    createdAt: {
      type: Date,
      default: Date.now
    }
  }],
  readBy: [{
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    readAt: {
      type: Date,
      default: Date.now
    }
  }],
  deliveredTo: [{
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    deliveredAt: {
      type: Date,
      default: Date.now
    }
  }],
  // Self-destruct
  selfDestruct: {
    enabled: {
      type: Boolean,
      default: false
    },
    duration: Number, // seconds
    viewedAt: Date
  },
  // Message status
  status: {
    type: String,
    enum: ['sending', 'sent', 'delivered', 'read', 'failed'],
    default: 'sent'
  },
  isEdited: {
    type: Boolean,
    default: false
  },
  editHistory: [{
    content: String,
    editedAt: {
      type: Date,
      default: Date.now
    }
  }],
  isDeleted: {
    type: Boolean,
    default: false
  },
  deletedAt: Date,
  deletedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }
}, {
  timestamps: true
});

// Index for search
messageSchema.index({ content: 'text' });
messageSchema.index({ room: 1, createdAt: -1 });

// Auto-delete self-destruct messages
messageSchema.pre('save', function(next) {
  if (this.selfDestruct.enabled && this.selfDestruct.viewedAt) {
    const deleteAt = new Date(this.selfDestruct.viewedAt.getTime() + this.selfDestruct.duration * 1000);
    // Schedule deletion (implement with node-cron or similar)
  }
  next();
});

module.exports = mongoose.model('Message', messageSchema);