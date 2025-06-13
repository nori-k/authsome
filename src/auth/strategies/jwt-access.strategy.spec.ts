import { describe, it, expect, vi } from 'vitest';
import { JwtAccessStrategy } from './jwt-access.strategy';
import type { PrismaService } from '../../prisma/prisma.service';

describe('JwtAccessStrategy', () => {
  it('should validate payload with sub', () => {
    const strategy = new JwtAccessStrategy({} as PrismaService);
    const payload = { sub: 'user-id' };
    expect(strategy.validate(payload)).toEqual({ id: 'user-id' });
  });

  it('should throw if payload.sub is missing', () => {
    const strategy = new JwtAccessStrategy({} as PrismaService);
    expect(() => strategy.validate({} as any)).toThrow();
  });

  it('should throw if payload is null', () => {
    const strategy = new JwtAccessStrategy({} as PrismaService);
    expect(() => strategy.validate(null as any)).toThrow();
  });

  it('should throw if payload is undefined', () => {
    const strategy = new JwtAccessStrategy({} as PrismaService);
    expect(() => strategy.validate(undefined as any)).toThrow();
  });

  it('should throw if payload.sub is not a string', () => {
    const strategy = new JwtAccessStrategy({} as PrismaService);
    expect(() => strategy.validate({ sub: 123 } as any)).toThrow();
  });
});
