// src/types/fastify.d.ts
import 'fastify';
import type { User } from '@prisma/client';

declare module 'fastify' {
  interface FastifyRequest {
    user?: User;
    cookies: Record<string, string>;
  }
  interface FastifyReply {
    setCookie(_: string, __: string, ___?: unknown): this;
    clearCookie(_: string, ___?: unknown): this;
  }
}

// 空interfaceをobject型に変更し、未使用引数は_で始める

type FastifyCookieOptions = object;

declare module 'fastify' {
  interface FastifyInstance {
    setCookie: (
      _name: string,
      _value: string,
      _options?: FastifyCookieOptions,
    ) => void;
    clearCookie: (_name: string, _options?: FastifyCookieOptions) => void;
  }
}
