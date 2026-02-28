const mongoose = require('mongoose');

const friendRequestSchema = new mongoose.Schema({
  sender: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  receiver: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  status: {
    type: String,
    enum: ['pending', 'accepted', 'rejected', 'blocked'],
    default: 'pending'
  },
  message: {
    type: String,
    maxlength: [200, 'Message cannot exceed 200 characters']
  },
  // Prevent duplicate requests
  uniquePair: {
    type: String,
    unique: true
  }
}, {
  timestamps: true
});

// Create unique pair before saving
friendRequestSchema.pre('save', function(next) {
  if (this.isNew) {
    const sorted = [this.sender.toString(), this.receiver.toString()].sort();
    this.uniquePair = `${sorted[0]}_${sorted[1]}`;
  }
  next();
});

// Indexes
friendRequestSchema.index({ sender: 1, receiver: 1 });
friendRequestSchema.index({ status: 1 });
friendRequestSchema.index({ createdAt: -1 });

module.exports = mongoose.model('FriendRequest', friendRequestSchema);