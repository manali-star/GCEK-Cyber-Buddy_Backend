// models/Chat.js
const mongoose = require('mongoose');

const messageSchema = new mongoose.Schema({
  sender: { type: String, required: true }, // 'user' or 'ai'
  text: { type: String, required: true },
  timestamp: { type: Date, default: Date.now },
  source: { type: String, default: '' }, // e.g., 'Gemini', 'Ollama', 'Rule-based'

  // 🔽 NEW: Optional file data
  file: {
    type: {
      type: String, // 'image' | 'text'
    },
    content: String, // base64 string or text
    name: String     // original file name
  }
});

const chatSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  title: { type: String, default: 'New Chat' },
  messages: [messageSchema],
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Chat', chatSchema);
