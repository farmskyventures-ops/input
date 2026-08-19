import { Request, Response, NextFunction } from 'express';

export const validateInternalRequest = (req: Request, res: Response, next: NextFunction) => {
  const secretHeader = req.headers['x-internal-secret'];
  const expectedSecret = process.env.FARMSKY_PAYMENTS_HMAC_SECRET;

  if (!secretHeader || secretHeader !== expectedSecret) {
    return res.status(401).json({ error: 'Unauthorized: Invalid or missing secret' });
  }

  next(); // Secret matches, proceed to the payment logic
};
