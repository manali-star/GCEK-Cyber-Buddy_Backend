const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const UserSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true,
    validate: {
      validator: (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email),
      message: 'Invalid email format'
    }
  },
  password: {
    type: String,
    required: function() {
      return this.authProvider === 'local';
    },
    minlength: [6, 'Password must be at least 6 characters']
  },
  resetPasswordToken: String,
  resetPasswordExpires: Date,

  // Enhanced Profile Fields
  name: {
    type: String,
    trim: true,
    maxlength: [50, 'Name cannot exceed 50 characters'],
    set: (name) => name ? name.trim() : name
  },
  avatar: {
    type: String,
    validate: {
      validator: (url) => {
        if (!url) return true; // Avatar is optional
        return url.startsWith('data:image/') || 
               url.startsWith('http://') || 
               url.startsWith('https://');
      },
      message: 'Avatar must be a valid image URL or Base64 string'
    }
  },
  authProvider: {
    type: String,
    enum: ['local', 'google'],
    default: 'local'
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  lastUpdated: {  // New field to track profile changes
    type: Date,
    default: Date.now
  }
}, {
  toJSON: {
    virtuals: true,
    transform: function(doc, ret) {
      delete ret.password;
      delete ret.resetPasswordToken;
      delete ret.resetPasswordExpires;
      return ret;
    }
  },
  toObject: { virtuals: true }
});

// Enhanced pre-save hooks
UserSchema.pre('save', async function(next) {
  if (this.authProvider !== 'local' || !this.isModified('password')) return next();
  
  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (err) {
    next(err);
  }
});

// Add default avatar fallback in User model
UserSchema.pre('save', function(next) {
  if (!this.avatar && this.authProvider === 'google') {
    this.avatar = `https://ui-avatars.com/api/?name=${encodeURIComponent(this.name || this.email)}&background=random`;
  }
  next();
});

// Helper method for profile updates
UserSchema.methods.updateProfile = async function(updates) {
  const allowedUpdates = ['name', 'avatar'];
  Object.keys(updates).forEach((key) => {
    if (allowedUpdates.includes(key)) {
      this[key] = updates[key];
    }
  });
  return this.save();
};

// Virtual for avatar URL (if using cloud storage later)
UserSchema.virtual('avatarUrl').get(function() {
  if (!this.avatar) return null;
  if (this.avatar.startsWith('http')) return this.avatar;
  return `/api/users/${this._id}/avatar`; // Example endpoint for serving avatars
});

module.exports = mongoose.model('User', UserSchema);