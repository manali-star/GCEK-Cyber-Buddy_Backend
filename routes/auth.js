const authMiddleware = require('../middleware/authMiddleware');

require('dotenv').config();
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const router = express.Router();
const multer = require('multer');


// Configure multer for file uploads
const upload = multer();


// 1. Email Configuration
const transporter = nodemailer.createTransport({
  service: 'Gmail',
  auth: {
    user: process.env.EMAIL_USERNAME,
    pass: process.env.EMAIL_PASSWORD
  }
});

// 2. Forgot Password Endpoint
router.post('/forgot-password', async (req, res) => {
  const { email } = req.body;
  
  try {
    // 2.1 Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.json({ message: 'If this email exists, a reset link has been sent.' });
    }

    // 2.2 Generate token
    const resetToken = crypto.randomBytes(20).toString('hex');
    user.resetPasswordToken = crypto.createHash('sha256').update(resetToken).digest('hex');
    user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
    await user.save();

    // 2.3 Send email
    const resetUrl = `${process.env.FRONTEND_URL}/reset-password?token=${resetToken}&email=${email}`;
    await transporter.sendMail({
      to: user.email,
      subject: 'Password Reset',
      html: `Click <a href="${resetUrl}">here</a> to reset your password. Link expires in 1 hour.`
    });

    res.json({ message: 'Reset email sent.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error sending email.' });
  }
});

// 3. Reset Password Endpoint
router.put('/reset-password', async (req, res) => {
  const { token, email, password } = req.body;

  try {
    // 3.1 Validate token
    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');
    const user = await User.findOne({
      email,
      resetPasswordToken: hashedToken,
      resetPasswordExpires: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).json({ message: 'Invalid or expired token.' });
    }

    // 3.2 Update password
    user.password = password;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();

    res.json({ message: 'Password updated successfully.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error resetting password.' });
  }
});



router.post('/register', async (req, res) => {
  const { email, password } = req.body;

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }

    const newUser = new User({ 
      email, 
      password,
      authProvider: 'local'
    });
    await newUser.save();

    const token = jwt.sign({ userId: newUser._id }, process.env.JWT_SECRET, { 
      expiresIn: '1d' 
    });

    res.status(201).json({ token });
  } catch (err) {
    console.error('Server error during registration:', err);
    res.status(500).json({ message: 'Server error during registration' });
  }
});

router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: 'Invalid credentials' });

    // Only check password for local auth users
    if (user.authProvider === 'local') {
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
      expiresIn: '1d'
    });

    res.status(200).json({ token });
  } catch (err) {
    console.error('Server error during login:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

router.post('/google', async (req, res) => {
  try {
    const { email, name, picture, isRegistering } = req.body;
    
    if (!email) {
      return res.status(400).json({ message: 'Email is required' });
    }

    // Check if user exists
    let user = await User.findOne({ email });
    
    if (!user) {
      if (isRegistering) {
        // Create new user during registration flow
        user = new User({
          email,
          name,
          avatar: picture,
          authProvider: 'google'
          // No password needed
        });
        await user.save();
      } else {
        // Return error during login flow
        return res.status(404).json({ 
          message: 'Account not registered. Please sign up first.',
          code: 'GOOGLE_ACCOUNT_NOT_REGISTERED'
        });
      }
    }

    // Generate JWT token
    const authToken = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
      expiresIn: '1d'
    });

    res.status(200).json({ token: authToken });
  } catch (err) {
    console.error('Google authentication error:', err);
    res.status(400).json({ 
      message: 'Google authentication failed',
      error: err.message 
    });
  }
});

// Get current user data
router.get('/me', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.userId)
      .select('-password -resetPasswordToken -resetPasswordExpires');
    
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    res.json({ 
      user: {
        _id: user._id,
        email: user.email,
        name: user.name,
        avatar: user.avatar,
        authProvider: user.authProvider,
        createdAt: user.createdAt
      }
    });
  } catch (err) {
    console.error('Error fetching user data:', err);
    res.status(500).json({ message: 'Error fetching user data' });
  }
});

// Update user name
router.put('/name', authMiddleware, async (req, res) => {
  try {
    if (!req.body.name || req.body.name.trim().length === 0) {
      return res.status(400).json({ message: 'Name cannot be empty' });
    }

    const user = await User.findByIdAndUpdate(
      req.userId,
      { name: req.body.name.trim() },
      { new: true }
    ).select('-password -resetPasswordToken -resetPasswordExpires');
    
    res.json({ 
      user: {
        _id: user._id,
        email: user.email,
        name: user.name,
        avatar: user.avatar,
        authProvider: user.authProvider
      }
    });
  } catch (err) {
    console.error('Error updating name:', err);
    res.status(500).json({ message: 'Error updating name' });
  }
});

// Update user avatar (using multer for file upload)
router.put('/avatar', authMiddleware, upload.single('avatar'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ message: 'No file uploaded' });
    }

    // Validate file type
    const validMimeTypes = ['image/jpeg', 'image/png', 'image/gif'];
    if (!validMimeTypes.includes(req.file.mimetype)) {
      return res.status(400).json({ message: 'Only JPEG, PNG, and GIF images are allowed' });
    }

    // Validate file size (max 2MB)
    if (req.file.size > 2 * 1024 * 1024) {
      return res.status(400).json({ message: 'Image size must be less than 2MB' });
    }

    const avatarUrl = `data:${req.file.mimetype};base64,${req.file.buffer.toString('base64')}`;

    const user = await User.findByIdAndUpdate(
      req.userId,
      { avatar: avatarUrl },
      { new: true }
    ).select('-password -resetPasswordToken -resetPasswordExpires');
    
    res.json({ 
      user: {
        _id: user._id,
        email: user.email,
        name: user.name,
        avatar: user.avatar,
        authProvider: user.authProvider
      }
    });
  } catch (err) {
    console.error('Error updating avatar:', err);
    res.status(500).json({ message: 'Error updating avatar' });
  }
});

// Change password
router.put('/password', authMiddleware, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ message: 'Both current and new password are required' });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({ message: 'Password must be at least 6 characters' });
    }

    const user = await User.findById(req.userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // For local auth users only
    if (user.authProvider === 'local') {
      const isMatch = await bcrypt.compare(currentPassword, user.password);
      if (!isMatch) {
        return res.status(400).json({ message: 'Current password is incorrect' });
      }

      const salt = await bcrypt.genSalt(10);
      user.password = await bcrypt.hash(newPassword, salt);
      await user.save();
    }

    res.json({ message: 'Password updated successfully' });
  } catch (err) {
    console.error('Error changing password:', err);
    res.status(500).json({ message: 'Error changing password' });
  }
});

module.exports = router;