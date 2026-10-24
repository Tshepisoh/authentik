import { pino, type Logger } from 'pino';
import type { Config } from '../config.js';

export function createLogger(config: Config): Logger {
  return pino({
    level: config.LOG_LEVEL,
    base: { service: 'authentik-api' },
    // Defence in depth: these must never reach logs even if someone logs a request object.
    redact: {
      paths: [
        'req.headers.authorization',
        'req.headers.cookie',
        'headers.authorization',
        '*.token',
        '*.idToken',
        '*.viewToken',
        '*.password',
        '*.secret',
      ],
      censor: '[redacted]',
    },
    transport:
      config.NODE_ENV === 'development' ? { target: 'pino-pretty', options: { colorize: true } } : undefined,
  });
}
