"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.sanitizeEmail = exports.validateEmail = exports.getCurrentTimestamp = void 0;
const getCurrentTimestamp = () => new Date().toISOString();
exports.getCurrentTimestamp = getCurrentTimestamp;
const validateEmail = (email) => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
};
exports.validateEmail = validateEmail;
const sanitizeEmail = (email) => email.trim().toLowerCase();
exports.sanitizeEmail = sanitizeEmail;
