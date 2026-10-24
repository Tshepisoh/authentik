import type { z } from 'zod';
import { badRequest } from './errors.js';

/** Parses untrusted input against a schema, throwing a 400 with field-level issues. */
export function parse<T extends z.ZodType>(schema: T, input: unknown): z.infer<T> {
  const result = schema.safeParse(input);
  if (!result.success) {
    throw badRequest(
      'invalid_request',
      'Some of the information sent was not valid.',
      result.error.issues.map((i) => ({ path: i.path.join('.'), message: i.message })),
    );
  }
  return result.data;
}
