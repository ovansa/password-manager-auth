"use strict";
/**
 * Structured logger with colored output for development, plain JSON for production.
 *
 * Dev (NODE_ENV !== 'production'): colored, human-readable lines to stdout/stderr.
 * Production: one JSON line per call - queryable in Railway's log viewer.
 *
 * Usage:
 *   logger.info('login.success', { email, durationMs });
 *   logger.warn('login.failed', { reason: 'bad_password', attempts: 3 });
 *   logger.error('register.error', error, { email });
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.logger = void 0;
// ── ANSI color codes ──────────────────────────────────────────────────────────
const c = {
    reset: '\x1b[0m',
    bold: '\x1b[1m',
    dim: '\x1b[2m',
    // levels
    info: '\x1b[36m', // cyan
    warn: '\x1b[33m', // yellow
    error: '\x1b[31m', // red
    fatal: '\x1b[35m', // magenta
    // accents
    gray: '\x1b[90m',
    white: '\x1b[97m',
};
const LEVEL_COLOR = {
    info: c.info,
    warn: c.warn,
    error: c.error,
    fatal: c.fatal,
};
const isProd = process.env.NODE_ENV === 'production';
function formatFields(fields) {
    return Object.entries(fields)
        .map(([k, v]) => `${c.gray}${k}${c.reset}=${c.white}${JSON.stringify(v)}${c.reset}`)
        .join(' ');
}
function writeDev(stream, level, event, fields) {
    const ts = new Date().toISOString().replace('T', ' ').replace('Z', '');
    const levelColor = LEVEL_COLOR[level] ?? c.info;
    const tag = `${levelColor}${c.bold}${level.toUpperCase().padEnd(5)}${c.reset}`;
    const fieldStr = Object.keys(fields).length
        ? '  ' + formatFields(fields)
        : '';
    const line = `${c.dim}${ts}${c.reset}  ${tag}  ${c.white}${event}${c.reset}${fieldStr}`;
    if (stream === 'stderr') {
        process.stderr.write(line + '\n');
    }
    else {
        process.stdout.write(line + '\n');
    }
}
function writeProd(stream, level, event, fields) {
    const line = JSON.stringify({
        level,
        event,
        ...fields,
        ts: new Date().toISOString(),
    });
    if (stream === 'stderr') {
        process.stderr.write(line + '\n');
    }
    else {
        process.stdout.write(line + '\n');
    }
}
function write(stream, level, event, fields) {
    if (isProd) {
        writeProd(stream, level, event, fields);
    }
    else {
        writeDev(stream, level, event, fields);
    }
}
exports.logger = {
    info(event, fields = {}) {
        write('stdout', 'info', event, fields);
    },
    warn(event, fields = {}) {
        write('stdout', 'warn', event, fields);
    },
    error(event, error, fields = {}) {
        const err = error;
        write('stderr', 'error', event, {
            ...fields,
            error: err.message ?? String(error),
            ...(err.code ? { code: err.code } : {}),
            // Omit stack in production to keep logs concise; include in dev
            ...(!isProd && err.stack ? { stack: err.stack } : {}),
        });
    },
    fatal(event, fields = {}) {
        write('stderr', 'fatal', event, fields);
    },
};
