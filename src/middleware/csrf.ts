import { Request, Response, NextFunction } from 'express';

export const csrfProtection = (req: Request, res: Response, next: NextFunction): void => {
  const xRequestedWith = req.get('X-Requested-With');
  if (!xRequestedWith || xRequestedWith !== 'XMLHttpRequest') {
    res.status(403).json({ error: 'CSRF protection: Invalid request' });
    return;
  }
  next();
};
