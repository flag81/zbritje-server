import pino from 'pino';
import { createRequire } from 'module';

const require = createRequire(import.meta.url);
const isDev = process.env.NODE_ENV !== 'production';

const opts = {
  level: process.env.LOG_LEVEL || (isDev ? 'debug' : 'info'),
  redact: {
    paths: ['req.headers.authorization', 'req.headers.cookie', 'body.password', 'body.token', 'body.secret'],
    censor: '[REDACTED]',
  },
  serializers: {
    err: pino.stdSerializers.err,
    error: pino.stdSerializers.err,
  },
};

const streams = [];

if (isDev) {
  streams.push({
    stream: pino.transport({
      target: require.resolve('pino-pretty'),
      options: { colorize: true, translateTime: 'SYS:standard', ignore: 'pid,hostname' },
    }),
  });
} else {
  streams.push({ stream: pino.destination(1) });
}

if (process.env.LOG_FILE) {
  streams.push({ stream: pino.destination({ dest: process.env.LOG_FILE, sync: true }) });
}

const baseLogger = streams.length > 1 ? pino(opts, pino.multistream(streams)) : pino(opts, streams[0].stream);

function toArgs(args) {
  if (args.length === 0) return { msg: '', extras: {} };

  const first = args[0];
  const rest = args.slice(1);

  if (rest.length === 0) {
    if (typeof first === 'string') return { msg: first, extras: {} };
    return { msg: '', extras: first };
  }

  if (rest.length === 1) {
    const second = rest[0];
    if (typeof first === 'string' && second !== null && typeof second === 'object') {
      return { msg: first, extras: second instanceof Error ? { err: second } : second };
    }
    if (typeof first === 'object' && typeof second === 'string') {
      return { msg: second, extras: first instanceof Error ? { err: first } : first };
    }
    return { msg: `${first} ${second}`, extras: {} };
  }

  return {
    msg: `${first} ${rest.map((v) => (v !== null && typeof v === 'object' ? JSON.stringify(v) : v)).join(' ')}`,
    extras: {},
  };
}

function adapt(logger) {
  return ['trace', 'debug', 'info', 'warn', 'error', 'fatal'].reduce(
    (acc, level) => {
      acc[level] = (...args) => {
        const { extras, msg } = toArgs(args);
        logger[level](extras, msg);
      };
      return acc;
    },
    {
      child: (bindings) => adapt(logger.child(bindings)),
      get level() {
        return logger.level;
      },
      get levelVal() {
        return logger.levelVal;
      },
    },
  );
}

const logger = adapt(baseLogger);

export default logger;
