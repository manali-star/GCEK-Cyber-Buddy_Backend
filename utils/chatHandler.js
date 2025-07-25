// utils/chatHandler.js
const axios = require('axios');
require('dotenv').config();

const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
const VIRUSTOTAL_API_KEY = process.env.VIRUSTOTAL_API_KEY;

/**
 * Sends message (and optional file) to Gemini model.
 */
async function callGemini(message, fileData = null) {
  if (!GEMINI_API_KEY) {
    throw new Error('GEMINI_API_KEY is not set in environment variables.');
  }

  try {
    const parts = [];
    // System prompt to guide Gemini's behavior
    parts.push({
      text: `You are GCEK Cyber Buddy, a virtual cyber security assistant developed for GCEK students. You must:
      - Only respond to greetings, queries about your name, or cyber security-related questions.
      - If a user asks about anything outside cyber security or your identity/greetings, simply reply: "I'm only able to answer questions that are related to cyber security."
      - If the user greets you, respond warmly as GCEK Cyber Buddy.
      - If the user asks your name or who you are, respond with: "I'm GCEK Cyber Buddy, your virtual cyber security assistant. I'm here to guide, protect, and support you in understanding digital threats, safe browsing, and online safety. Let's secure your digital world together!"`
    });

    if (fileData?.type === 'image' && fileData?.content) {
      parts.push({
        inline_data: {
          mime_type: 'image/png',
          data: fileData.content.split(',')[1]
        }
      });
    }

    parts.push({ text: message });

    const payload = {
      contents: [{ role: 'user', parts }]
    };

    const response = await axios.post(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${GEMINI_API_KEY}`,
      payload,
      { headers: { 'Content-Type': 'application/json' } }
    );

    const candidates = response.data.candidates;
    if (candidates?.length > 0 && candidates[0].content?.parts?.[0]?.text) {
      return candidates[0].content.parts[0].text;
    }

    throw new Error('No valid response from Gemini API');
  } catch (error) {
    throw new Error(`Gemini API request failed: ${error.message}`);
  }
}

/**
 * Sends a URL or file hash to VirusTotal for scanning.
 * @param {string} resource The URL or file hash to scan.
 * @param {string} type 'url' or 'file_hash'.
 */
/**
 * Sends a URL to VirusTotal for scanning.
 * @param {string} url The URL to scan.
 */
async function callVirusTotal(url) {
  if (!VIRUSTOTAL_API_KEY) {
    throw new Error('VIRUSTOTAL_API_KEY is not set in environment variables.');
  }

  if (!url || typeof url !== 'string') {
    throw new Error('URL is required and must be a string');
  }

  try {
    const headers = {
      'x-apikey': VIRUSTOTAL_API_KEY,
      'Content-Type': 'application/x-www-form-urlencoded'
    };

    // Step 1: Submit URL for scanning
    const formData = new URLSearchParams();
    formData.append('url', url);

    const submitResponse = await axios.post(
      'https://www.virustotal.com/api/v3/urls',
      formData,
      { headers }
    );

    const analysisId = submitResponse.data.data.id;

    // Step 2: Retrieve analysis results
    let attempts = 0;
    const maxAttempts = 10;
    const delay = 3000; // 3 seconds between attempts

    while (attempts < maxAttempts) {
      await new Promise(resolve => setTimeout(resolve, delay));

      const analysisResponse = await axios.get(
        `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
        { headers }
      );

      const status = analysisResponse.data.data.attributes.status;

      if (status === 'completed') {
        const results = analysisResponse.data.data.attributes.results;
        const stats = analysisResponse.data.data.attributes.stats;

        return {
          id: analysisId,
          url: url,
          malicious: stats.malicious,
          harmless: stats.harmless,
          suspicious: stats.suspicious,
          undetected: stats.undetected,
          timeout: stats.timeout,
          results: results,
          permalink: `https://www.virustotal.com/gui/url/${analysisId}/detection`
        };
      }

      attempts++;
    }

    throw new Error('VirusTotal analysis timed out after maximum attempts');

  } catch (error) {
    console.error('VirusTotal API error:', error.response?.data || error.message);
    throw new Error(`VirusTotal scan failed: ${error.response?.data?.error?.message || error.message}`);
  }
}

module.exports = {
  callGemini: callGemini,  // Keeping original export name
  callVirusTotal: callVirusTotal  // Keeping original export name
};