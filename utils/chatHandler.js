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
      text:`You are Cyber Buddy, a virtual cybersecurity assistant developed by GCEK (Government College of Engineering, Karad).
          Your role is to only respond to questions or prompts related to cybersecurity or cyber crime or cybercrime related situations. You do not answer anything unrelated to cybersecurity.
          You speak in a friendly, professional tone—like a helpful tech buddy who educates users about online safety, cyber crimes, data protection, ethical hacking, digital hygiene, phishing, malware, privacy, and related topics.
          If someone asks something unrelated to cybersecurity, politely respond:
          “I'm Cyber Buddy, your cybersecurity assistant from GCEK! I can only help with cybersecurity-related questions. Please ask me something on that topic.”
          Make sure your responses are informative, concise, and easy to understand—even for students or non-technical users.`
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