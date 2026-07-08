import logger from '../services/logger.js';

export function requestLogger(req, res, next) {
  const reqId = `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
  req.reqId = reqId;
  req.log = logger.child({ reqId, method: req.method, url: req.originalUrl });

  const start = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - start;
    const level = res.statusCode >= 500 ? 'error' : res.statusCode >= 400 ? 'warn' : 'info';
    req.log[level]({ statusCode: res.statusCode, duration }, 'request completed');
  });

  req.log.debug('request started');
  next();
}
