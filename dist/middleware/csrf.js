"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.csrfProtection = void 0;
const csrfProtection = (req, res, next) => {
    const xRequestedWith = req.get('X-Requested-With');
    if (!xRequestedWith || xRequestedWith !== 'XMLHttpRequest') {
        res.status(403).json({ error: 'CSRF protection: Invalid request' });
        return;
    }
    next();
};
exports.csrfProtection = csrfProtection;
