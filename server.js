require('dotenv').config();
const express = require('express');
const axios = require('axios');
const cors = require('cors');

const app = express();

// Middleware
// app.use(
//   cors({
//     origin: [
//       'chrome-extension://YOUR_EXTENSION_ID', // Chrome
//       'moz-extension://YOUR_FIREFOX_ID', // Firefox
//     ],
//     credentials: true,
//   })
// );
app.use(express.json());

// Helper function to get current timestamp
const getCurrentTimestamp = () => {
  return new Date().toISOString();
};

console.log('Environment Variables:', {
  timestamp: getCurrentTimestamp(),
  clientId: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  redirectUri: process.env.REDIRECT_URI,
});

// Route: Exchange auth code for tokens
app.post('/api/auth/google', async (req, res) => {
  const requestTimestamp = getCurrentTimestamp();
  console.log('Received request to exchange auth code for tokens', {
    timestamp: requestTimestamp,
    body: req.body,
  });

  try {
    const { code } = req.body;

    const response = await axios.post(
      'https://oauth2.googleapis.com/token',
      new URLSearchParams({
        code,
        client_id: process.env.GOOGLE_CLIENT_ID,
        client_secret: process.env.GOOGLE_CLIENT_SECRET,
        redirect_uri: process.env.REDIRECT_URI,
        grant_type: 'authorization_code',
      }),
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
      }
    );

    const responseTimestamp = getCurrentTimestamp();
    console.log('Successfully exchanged auth code for tokens', {
      timestamp: responseTimestamp,
      duration: `${new Date(responseTimestamp) - new Date(requestTimestamp)}ms`,
    });

    res.json({
      access_token: response.data.access_token,
      refresh_token: response.data.refresh_token,
      expires_in: response.data.expires_in,
      timestamp: responseTimestamp,
    });
  } catch (error) {
    const errorTimestamp = getCurrentTimestamp();
    console.error('OAuth error:', {
      timestamp: errorTimestamp,
      requestTime: requestTimestamp,
      errorTime: errorTimestamp,
      duration: `${new Date(errorTimestamp) - new Date(requestTimestamp)}ms`,
      request: error.config?.data,
      response: error.response?.data,
      error: error.message,
    });

    res.status(400).json({
      error: 'Authentication failed',
      details: error.response?.data,
      timestamp: errorTimestamp,
    });
  }
});

// Route: Refresh access token
app.post('/api/auth/refresh', async (req, res) => {
  const requestTimestamp = getCurrentTimestamp();
  console.log('Received refresh token request', {
    timestamp: requestTimestamp,
  });

  try {
    const { refresh_token } = req.body;

    const response = await axios.post('https://oauth2.googleapis.com/token', {
      refresh_token,
      client_id: process.env.GOOGLE_CLIENT_ID,
      client_secret: process.env.GOOGLE_CLIENT_SECRET,
      grant_type: 'refresh_token',
    });

    const responseTimestamp = getCurrentTimestamp();
    console.log('Successfully refreshed access token', {
      timestamp: responseTimestamp,
      duration: `${new Date(responseTimestamp) - new Date(requestTimestamp)}ms`,
    });

    res.json({
      access_token: response.data.access_token,
      expires_in: response.data.expires_in,
      timestamp: responseTimestamp,
    });
  } catch (error) {
    const errorTimestamp = getCurrentTimestamp();
    console.error('Refresh error:', {
      timestamp: errorTimestamp,
      requestTime: requestTimestamp,
      errorTime: errorTimestamp,
      duration: `${new Date(errorTimestamp) - new Date(requestTimestamp)}ms`,
      response: error.response?.data,
      error: error.message,
    });

    res.status(400).json({
      error: 'Token refresh failed',
      timestamp: errorTimestamp,
    });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () =>
  console.log(`[${getCurrentTimestamp()}] Server running on port ${PORT}`)
);
