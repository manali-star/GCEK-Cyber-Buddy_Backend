const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
require('dotenv').config();

const authRoutes = require('./routes/auth');
const chatRoutes = require('./routes/chat');

const app = express();


// Middlewares

const allowedOrigins = [
  'https://gcek-cyber-buddy-frontend.vercel.app',
  'http://localhost:3000' // optional, for local dev
];

app.use(cors({
  origin: allowedOrigins,
  credentials: true
}));

app.options('*', cors()); // preflight support


app.use(express.json({ limit: '10mb' }));

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/chat', chatRoutes);

// Default route
app.get('/', (req, res) => {
  res.send('AI Chatbot Server Running');
});

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => console.log('✅ Connected to MongoDB Atlas'))
  .catch(err => console.error('❌ MongoDB error:', err));

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`✅ Server running on http://localhost:${PORT}`);
});
