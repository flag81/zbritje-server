import logger from '../services/logger.js';
export function errorHandler(err, req, res, next) {
  logger.error(`[ErrorHandler] ${err.message || err}`);
  if (res.headersSent) return next(err);
  res.status(err.status || 500).json({
    error: err.message || 'Internal server error',
  });
}

export function notFoundHandler(req, res) {
  res.status(404).json({ error: `Route not found: ${req.method} ${req.originalUrl}` });
}
