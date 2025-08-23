require('dotenv').config();
const express = require('express');
const axios = require('axios');
const cors = require('cors');
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');

const app = express();

// Security middleware
app.use(helmet());
app.use(express.json({ limit: '10mb' }));

// Rate limiting
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts per window
  message: { error: 'Too many authentication attempts, try again later' },
  standardHeaders: true,
  legacyHeaders: false,
});

const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // 100 requests per window
  standardHeaders: true,
  legacyHeaders: false,
});

app.use('/api/auth', authLimiter);
app.use(generalLimiter);

// CORS configuration
app.use(
  cors({
    origin:
      process.env.NODE_ENV === 'production'
        ? [process.env.FRONTEND_URL]
        : ['http://localhost:3000', 'http://127.0.0.1:3000'],
    credentials: true,
  })
);

// Initialize Firebase with the provided configuration
const { initializeApp } = require('firebase/app');
const {
  getFirestore,
  collection,
  doc,
  getDoc,
  setDoc,
  updateDoc,
  runTransaction,
} = require('firebase/firestore');

const firebaseConfig = {
  apiKey: process.env.FIREBASE_API_KEY,
  authDomain: process.env.FIREBASE_AUTH_DOMAIN,
  projectId: process.env.FIREBASE_PROJECT_ID,
  storageBucket: process.env.FIREBASE_STORAGE_BUCKET,
  messagingSenderId: process.env.FIREBASE_MESSAGING_SENDER_ID,
  appId: process.env.FIREBASE_APP_ID,
  measurementId: process.env.FIREBASE_MEASUREMENT_ID,
};

// Initialize Firebase
const firebaseApp = initializeApp(firebaseConfig);
const db = getFirestore(firebaseApp);
console.log('Firebase initialized successfully');

// Helper functions
const getCurrentTimestamp = () => new Date().toISOString();

const validateEmail = (email) => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
};

const sanitizeEmail = (email) => {
  return email.trim().toLowerCase();
};

// CSRF protection middleware
const csrfProtection = (req, res, next) => {
  const xRequestedWith = req.get('X-Requested-With');
  if (!xRequestedWith || xRequestedWith !== 'XMLHttpRequest') {
    return res.status(403).json({ error: 'CSRF protection: Invalid request' });
  }
  next();
};

// ============= AUTH ENDPOINTS =============

// Route: Register new user
app.post('/api/auth/register', csrfProtection, async (req, res) => {
  const requestTimestamp = getCurrentTimestamp();
  console.log('User registration attempt', {
    timestamp: requestTimestamp,
    ip: req.ip,
  });

  try {
    const { email, passwordHash, kdfIterations, kdfType } = req.body;

    // Validation
    if (!email || !passwordHash || !kdfIterations || !kdfType) {
      return res.status(400).json({
        success: false,
        error: 'Missing required fields',
      });
    }

    const sanitizedEmail = sanitizeEmail(email);
    if (!validateEmail(sanitizedEmail)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid email format',
      });
    }

    // Validate KDF parameters
    if (kdfIterations < 100000 || kdfIterations > 2000000) {
      return res.status(400).json({
        success: false,
        error: 'Invalid KDF iterations',
      });
    }

    // Check if user already exists
    const userRef = doc(db, 'users', sanitizedEmail);
    const userDoc = await getDoc(userRef);

    if (userDoc.exists()) {
      console.log('Registration failed - user exists', {
        timestamp: getCurrentTimestamp(),
        email: sanitizedEmail,
      });
      return res.status(400).json({ success: false });
    }

    // Check subscription status
    const hasValidSubscription = await checkSubscriptionStatus(sanitizedEmail);
    if (!hasValidSubscription) {
      console.log('Registration failed - no subscription', {
        timestamp: getCurrentTimestamp(),
        email: sanitizedEmail,
      });
      return res.status(400).json({ success: false });
    }

    // Hash the password hash again server-side
    const serverHash = await bcrypt.hash(passwordHash, 12);

    // Create user document
    const userData = {
      email: sanitizedEmail,
      authHash: serverHash,
      kdfIterations: parseInt(kdfIterations),
      kdfType: kdfType,
      isSubscribed: true,
      createdAt: new Date(),
      lastLogin: null,
      isActive: true,
      loginAttempts: 0,
      lockedUntil: null,
    };

    await setDoc(userRef, userData);

    console.log('User registered successfully', {
      timestamp: getCurrentTimestamp(),
      email: sanitizedEmail,
      duration: `${Date.now() - new Date(requestTimestamp).getTime()}ms`,
    });

    res.json({ success: true });
  } catch (error) {
    const errorTimestamp = getCurrentTimestamp();
    console.error('Registration error:', {
      timestamp: errorTimestamp,
      error: error.message,
      duration: `${Date.now() - new Date(requestTimestamp).getTime()}ms`,
    });

    res.status(500).json({
      success: false,
      error: 'Registration failed',
    });
  }
});

// Route: User login
app.post('/api/auth/login', csrfProtection, async (req, res) => {
  const requestTimestamp = getCurrentTimestamp();
  console.log('Login attempt', {
    timestamp: requestTimestamp,
    ip: req.ip,
  });

  try {
    const { email, passwordHash } = req.body;

    if (!email || !passwordHash) {
      return res.status(400).json({
        success: false,
        error: 'Missing credentials',
      });
    }

    const sanitizedEmail = sanitizeEmail(email);
    const userRef = doc(db, 'users', sanitizedEmail);
    const userDoc = await getDoc(userRef);

    if (!userDoc.exists()) {
      // Consistent timing to prevent user enumeration
      await bcrypt.hash('dummy_password', 12);
      return res.status(401).json({
        success: false,
        error: 'Invalid credentials',
      });
    }

    const user = userDoc.data();

    // Check if account is locked
    if (user.lockedUntil && new Date() < user.lockedUntil.toDate()) {
      return res.status(423).json({
        success: false,
        error: 'Account temporarily locked',
      });
    }

    // Verify password hash
    const isValidPassword = await bcrypt.compare(passwordHash, user.authHash);

    if (!isValidPassword) {
      // Increment failed login attempts
      const attempts = (user.loginAttempts || 0) + 1;
      const updates = { loginAttempts: attempts };

      // Lock account after 5 failed attempts
      if (attempts >= 5) {
        updates.lockedUntil = new Date(Date.now() + 30 * 60 * 1000); // 30 minutes
      }

      await updateDoc(userRef, updates);

      return res.status(401).json({
        success: false,
        error: 'Invalid credentials',
      });
    }

    // Successful login - reset attempts and update last login
    await updateDoc(userRef, {
      loginAttempts: 0,
      lockedUntil: null,
      lastLogin: new Date(),
    });

    console.log('Successful login', {
      timestamp: getCurrentTimestamp(),
      email: sanitizedEmail,
      duration: `${Date.now() - new Date(requestTimestamp).getTime()}ms`,
    });

    // Return user data (excluding sensitive info)
    res.json({
      success: true,
      user: {
        email: user.email,
        kdfIterations: user.kdfIterations,
        kdfType: user.kdfType,
        isSubscribed: user.isSubscribed,
      },
    });
  } catch (error) {
    console.error('Login error:', {
      timestamp: getCurrentTimestamp(),
      error: error.message,
      duration: `${Date.now() - new Date(requestTimestamp).getTime()}ms`,
    });

    res.status(500).json({
      success: false,
      error: 'Login failed',
    });
  }
});

// Route: Get KDF parameters for a user
app.get('/api/auth/kdf-params', async (req, res) => {
  try {
    const { email } = req.query;

    if (!email) {
      return res.status(400).json({ error: 'Email required' });
    }

    const sanitizedEmail = sanitizeEmail(email);
    if (!validateEmail(sanitizedEmail)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }

    const userDoc = await getDoc(doc(db, 'users', sanitizedEmail));

    if (!userDoc.exists()) {
      // Return default parameters to prevent user enumeration
      return res.json({
        iterations: 310000,
        type: 'pbkdf2-sha256',
      });
    }

    const user = userDoc.data();
    res.json({
      iterations: user.kdfIterations,
      type: user.kdfType,
    });
  } catch (error) {
    console.error('KDF params error:', error.message);
    res.status(500).json({ error: 'Failed to get parameters' });
  }
});

// Route: Check subscription eligibility
app.post('/api/subscription/check-eligibility', async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ eligible: false });
    }

    const sanitizedEmail = sanitizeEmail(email);
    const hasSubscription = await checkSubscriptionStatus(sanitizedEmail);

    res.json({ eligible: hasSubscription });
  } catch (error) {
    console.error('Subscription check error:', error.message);
    res.status(500).json({ eligible: false });
  }
});

// ============= EXISTING GOOGLE OAUTH ENDPOINTS =============

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

// ============= HELPER FUNCTIONS =============

/**
 * Check if user has valid subscription
 * Implement your subscription logic here
 */
async function checkSubscriptionStatus(email) {
  try {
    // For development, allow all users
    if (process.env.NODE_ENV === 'development') {
      return true;
    }

    // Check if user exists and has subscription
    const userDoc = await getDoc(doc(db, 'users', email));
    if (userDoc.exists()) {
      const userData = userDoc.data();
      return userData.isSubscribed === true;
    }

    return false;
  } catch (error) {
    console.error('Subscription check failed:', error.message);
    return false;
  }
}

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('Unhandled error:', {
    timestamp: getCurrentTimestamp(),
    error: error.message,
    stack: error.stack,
    url: req.url,
    method: req.method,
  });

  res.status(500).json({
    error: 'Internal server error',
    timestamp: getCurrentTimestamp(),
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    error: 'Endpoint not found',
    timestamp: getCurrentTimestamp(),
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () =>
  console.log(`[${getCurrentTimestamp()}] Server running on port ${PORT}`)
);
