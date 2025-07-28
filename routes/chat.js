// routes/chat.js
const express = require('express');
const router = express.Router();
const authMiddleware = require('../middleware/authMiddleware');
const Chat = require('../models/Chat');
const mongoose = require('mongoose');
const { callGemini, callVirusTotal } = require('../utils/chatHandler');

// Unified chat endpoint
router.post('/', authMiddleware, async (req, res) => {
  const { message, sessionId, fileData } = req.body;
  const userId = req.userId;

  if (!message || typeof message !== 'string') {
    return res.status(400).json({ success: false, message: 'Message is required' });
  }

  try {
    let combinedInput = message.trim();
    if (fileData?.type === 'text') {
      combinedInput += `\n\nFile content:\n${fileData.content}`;
    } else if (fileData?.type === 'image') {
      combinedInput += `\n\n[Image uploaded: ${fileData.name || 'image'}]`;
    }

    // Special handling for URL scan results
    if (message.includes("🔍 URL Scan Results for:")) {
      const reply = "Here is the result of your URL, Thanks ";

      let chat = null;
      let newSessionId = sessionId;

      if (sessionId && mongoose.Types.ObjectId.isValid(sessionId)) {
        chat = await Chat.findOne({ _id: sessionId, user: userId });
      }

      if (chat) {
        chat.messages.push(
          { sender: 'user', text: message.trim(), timestamp: new Date(), file: fileData || undefined },
          { sender: 'ai', text: reply, source: 'GCEK Cyber Buddy', timestamp: new Date() }
        );
        chat.updatedAt = new Date();
        await chat.save();
      } else {
        chat = new Chat({
          user: userId,
          title: message.substring(0, 30) + (message.length > 30 ? '...' : ''),
          messages: [
            { sender: 'user', text: message.trim(), timestamp: new Date(), file: fileData || undefined },
            { sender: 'ai', text: reply, source: 'GCEK Cyber Buddy', timestamp: new Date() }
          ]
        });
        await chat.save();
        newSessionId = chat._id;
      }

      return res.json({ success: true, response: reply, source: 'GCEK Cyber Buddy', sessionId: newSessionId });
    }

    // Regular Gemini call
    let reply = await callGemini(combinedInput);

    let chat = null;
    let newSessionId = sessionId;

    if (sessionId && mongoose.Types.ObjectId.isValid(sessionId)) {
      chat = await Chat.findOne({ _id: sessionId, user: userId });
    }

    if (chat) {
      chat.messages.push(
        { sender: 'user', text: message.trim(), timestamp: new Date(), file: fileData || undefined },
        { sender: 'ai', text: reply, source: 'GCEK Cyber Buddy', timestamp: new Date() }
      );
      chat.updatedAt = new Date();
      await chat.save();
    } else {
      chat = new Chat({
        user: userId,
        title: message.substring(0, 30) + (message.length > 30 ? '...' : ''),
        messages: [
          { sender: 'user', text: message.trim(), timestamp: new Date(), file: fileData || undefined },
          { sender: 'ai', text: reply, source: 'GCEK Cyber Buddy', timestamp: new Date() }
        ]
      });
      await chat.save();
      newSessionId = chat._id;
    }

    res.json({ success: true, response: reply, source: 'GCEK Cyber Buddy', sessionId: newSessionId });
  } catch (err) {
    console.error('Chat error:', err);
    res.status(500).json({ success: false, message: 'Failed to process message', error: err.message });
  }
});


// In your route handler
router.post('/virustotal-scan', authMiddleware, async (req, res) => {
  try {
    const { url } = req.body;

    if (!url) {
      return res.status(400).json({ error: 'URL parameter is required' });
    }

    const result = await callVirusTotal(url);
    res.json(result);

  } catch (error) {
    console.error('VirusTotal scan failed:', error);
    res.status(500).json({ error: error.message });
  }
});

// Get chat history
router.get('/history', authMiddleware, async (req, res) => {
  try {
    const chats = await Chat.find({ user: req.userId }).sort({ createdAt: -1 });
    res.status(200).json({ success: true, history: chats });
  } catch (err) {
    console.error('History fetch error:', err);
    res.status(500).json({ success: false, message: 'Failed to fetch history' });
  }
});

// Delete chat
router.delete('/:id', authMiddleware, async (req, res) => {
  try {
    const result = await Chat.deleteOne({ _id: req.params.id, user: req.userId });
    if (result.deletedCount > 0) {
      res.status(200).json({ success: true, message: 'Chat deleted' });
    } else {
      res.status(404).json({ success: false, message: 'Chat not found' });
    }
  } catch (err) {
    console.error('Delete error:', err);
    res.status(500).json({ success: false, message: 'Failed to delete chat' });
  }
});

// Edit message and re-generate AI response
router.put('/editMessage', authMiddleware, async (req, res) => {
  const { sessionId, userIndex, newText } = req.body;

  try {
    const session = await Chat.findById(sessionId);
    if (!session) return res.status(404).json({ message: 'Chat not found' });

    if (!session.messages[userIndex] || session.messages[userIndex].sender !== 'user') {
      return res.status(400).json({ message: 'Invalid user message index' });
    }

    // Remove old user+AI pair
    session.messages.splice(userIndex, 2);

    const updatedUserMsg = { sender: 'user', text: newText, timestamp: new Date() };
    let aiText = await callGemini(newText);
    aiText = maskIdentity(aiText);
    const updatedAiMsg = { sender: 'ai', text: aiText, source: 'GCEK Cyber Buddy', timestamp: new Date() };

    session.messages.splice(userIndex, 0, updatedUserMsg, updatedAiMsg);
    session.updatedAt = new Date();
    if (userIndex === 0) {
      session.title = newText.substring(0, 30) + (newText.length > 30 ? '...' : '');
    }

    await session.save();

    res.json({ userMessage: updatedUserMsg, aiMessage: updatedAiMsg });
  } catch (err) {
    console.error('Edit error:', err);
    res.status(500).json({ message: 'Failed to edit message' });
  }
});

module.exports = router;
