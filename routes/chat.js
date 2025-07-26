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
          { sender: 'ai', text: reply, source: 'GCEK Cyber buddy', timestamp: new Date() }
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

    const isCyberSecurityQuery = (text) => {
      if (!text) return false;

      const keywords = [
        "cyber security", "malware", "phishing", "ransomware", "safe browsing", "online safety",
        "cyber attack", "firewall", "vpn", "encryption", "cyber threat", "data breach", "hacking",
        "secure password", "virus", "ddos", "2fa", "authentication", "otp", "cybercrime", "cyberbullying",
        "trojan", "spyware", "rootkit", "zero-day", "keylogger", "botnet", "identity theft", "social engineering",
        "brute force", "backdoor", "patch management", "security audit", "penetration testing", "vulnerability",
        "exploit", "access control", "network security", "application security", "endpoint security",
        "information security", "cloud security", "mobile security", "web security", "sql injection",
        "cross-site scripting", "xss", "csrf", "man-in-the-middle", "mitm", "spoofing", "digital forensics",
        "incident response", "threat intelligence", "risk assessment", "cyber hygiene", "security awareness",
        "security policy", "compliance", "gdpr", "hipaa", "iso 27001", "tls", "ssl", "public key", "private key",
        "hashing", "blockchain security", "biometric authentication", "security token", "session hijacking",
        "honeypot", "sandboxing", "network segmentation", "access logs", "cyber forensics", "ip spoofing",
        "mac spoofing", "packet sniffing", "intrusion detection", "intrusion prevention", "siem", "soc",
        "threat modeling", "cyber insurance", "bug bounty", "ethical hacking", "white hat", "black hat",
        "gray hat", "cyber law", "digital footprint", "cyber espionage", "cyber warfare", "surveillance",
        "privacy", "deep web", "dark web", "security breach", "insider threat", "security patch",
        "zero trust", "multi-factor authentication", "mfa", "tokenization", "password manager",
        "browser isolation", "attack vector", "security posture", "security incident", "recovery plan",
        "cyber resilience", "data loss prevention", "dlp", "log monitoring"

      ];

      const greetings = ["hi", "hello", "hey", "good morning", "good evening", "greetings"];
      const identityQueries = [
        "who are you", "your name", "what's your name", "tell me your name", "who is this", "what are you"
      ];

      const lowerText = text.toLowerCase();

      return (
        keywords.some(keyword => lowerText.includes(keyword)) ||
        greetings.some(greet => lowerText.includes(greet)) ||
        identityQueries.some(q => lowerText.includes(q))
      );
    };

    const cyberBuddyIntro = "I'm GCEK Cyber Buddy, your virtual cyber security assistant. I'm here to guide, protect, and support you in understanding digital threats, safe browsing, and online safety. Let's secure your digital world together!";

    const maskIdentity = (text, userQuery = '') => {
      if (!userQuery || typeof userQuery !== 'string') {
        return text; // Return original text if no user query provided
      }

      const lowerQuery = userQuery.toLowerCase();

      // Respond to greeting
      const greetings = ["hi", "hello", "hey", "good morning", "good evening", "greetings"];
      if (greetings.some(g => lowerQuery.includes(g))) {
        return `Hello! ${cyberBuddyIntro}`;
      }

      // Respond to name/identity questions
      const nameQueries = ["who are you", "your name", "what's your name", "tell me your name", "who is this", "what are you"];
      if (nameQueries.some(q => lowerQuery.includes(q))) {
        return cyberBuddyIntro;
      }

      // Filter out non-cybersecurity content
      if (!isCyberSecurityQuery(userQuery)) {
        return "I'm only able to answer questions that are related to cyber security.";
      }

      // Replace AI identity with Cyber Buddy branding
      return text
        .replace(/I am [^.]*\./gi, cyberBuddyIntro)
        .replace(/I am a large language model[^.]*\./gi, cyberBuddyIntro)
        .replace(/I am an? AI[^.]*\./gi, cyberBuddyIntro)
        .replace(/\b(gemini|google)\b/gi, "GCEK Cyber Buddy");
    };

    let reply = await callGemini(combinedInput);
    reply = maskIdentity(reply, message); // Pass the original message as userQuery

    let chat = null;
    let newSessionId = sessionId;

    if (sessionId && mongoose.Types.ObjectId.isValid(sessionId)) {
      chat = await Chat.findOne({ _id: sessionId, user: userId });
    }

    if (chat) {
      chat.messages.push(
        { sender: 'user', text: message.trim(), timestamp: new Date(), file: fileData || undefined },
        { sender: 'ai', text: reply, source: 'GCEK Cyber buddy', timestamp: new Date() }
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
