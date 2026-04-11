import 'dotenv/config';
import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import helmet from 'helmet';

import { generalLimiter } from './middleware/rateLimiters';
import { getCurrentTimestamp } from './helpers/email';
import { logger } from './helpers/logger';

// Firebase must be initialized before any route module imports db.
import './config/firebase';

import authRouter from './routes/auth';
import oauthRouter from './routes/oauth';
import licenseRouter from './routes/license';
import analyticsRouter from './routes/analytics';
import configRouter from './routes/config';

const app = express();

// Security middleware
app.use(helmet());
app.use(express.json({ limit: '10mb' }));

// CORS must run before rate limiters so that 429 responses still include
// Access-Control-Allow-Origin and are not blocked by the browser.
const allowedOrigins = [
  ...(process.env.FRONTEND_URL ? [process.env.FRONTEND_URL] : []),
  'http://localhost:3000',
  'http://127.0.0.1:3000',
];

app.use(
  cors({
    origin: (origin, callback) => {
      if (
        !origin ||
        origin.startsWith('chrome-extension://') ||
        origin.startsWith('moz-extension://') ||
        allowedOrigins.includes(origin)
      ) {
        callback(null, true);
      } else {
        callback(new Error(`CORS: origin ${origin} not allowed`));
      }
    },
    credentials: true,
  }),
);

// Apply general limiter globally, excluding the OAuth relay poll route.
app.use((req: Request, res: Response, next: NextFunction) => {
  if (req.path === '/api/auth/google/code') return next();
  generalLimiter(req, res, next);
});

// ── Routes ─────────────────────────────────────────────────────────────────
// Order matters: more specific paths must be mounted before broader ones.
// /api/auth/google/* must come before /api/auth/* so the google sub-router
// matches before Express strips the prefix.
app.use('/api/auth/google', oauthRouter);   // /callback, /code, /redirect-uri, POST /
app.use('/api/auth', authRouter);           // /register, /login, /kdf-params, /refresh
app.use('/api/subscription', licenseRouter);
app.use('/api/license', licenseRouter);
app.use('/api/analytics', analyticsRouter);
app.use('/api/config', configRouter);

// ── Error handlers ─────────────────────────────────────────────────────────

// Global error handler (4 params required for Express to treat as error handler)
app.use((error: Error, req: Request, res: Response, _next: NextFunction) => {
  logger.error('app.unhandled_error', error, { method: req.method, url: req.url });
  res.status(500).json({ error: 'Internal server error', timestamp: getCurrentTimestamp() });
});

// 404 handler
app.use((_req: Request, res: Response) => {
  res.status(404).json({ error: 'Endpoint not found', timestamp: getCurrentTimestamp() });
});

export { app };
