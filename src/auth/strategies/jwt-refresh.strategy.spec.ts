import { describe, it, expect, vi } from 'vitest';
import { JwtRefreshStrategy } from './jwt-refresh.strategy';
import type { PrismaService } from '../../prisma/prisma.service';
vi.mock('bcryptjs', () => ({
  compareSync: vi.fn(() => true),
}));
import * as bcrypt from 'bcryptjs';
import type { FastifyRequest } from 'fastify';

describe('JwtRefreshStrategy', () => {
  beforeEach(() => {
    (bcrypt.compareSync as ReturnType<typeof vi.fn>).mockReset();
    (bcrypt.compareSync as ReturnType<typeof vi.fn>).mockReturnValue(true);
  });

  it('should construct with secret', () => {
    expect(() => new JwtRefreshStrategy({} as PrismaService)).not.toThrow();
  });

  it('should throw if user not found', async () => {
    const prisma = {
      user: { findUnique: vi.fn().mockResolvedValue(null) },
    } as unknown as PrismaService;
    const strategy = new JwtRefreshStrategy(prisma);
    const req = {
      cookies: { refresh_token: 't' },
    } as unknown as FastifyRequest;
    await expect(strategy.validate({ sub: 'uid' }, req)).rejects.toThrow(
      'Refresh token invalid or user not found',
    );
  });

  it('should throw if refresh_token is missing', async () => {
    const prisma = {
      user: { findUnique: vi.fn().mockResolvedValue({ id: 'uid' }) },
    } as unknown as PrismaService;
    const strategy = new JwtRefreshStrategy(prisma);
    const req = {
      cookies: {},
    } as unknown as FastifyRequest;
    await expect(strategy.validate({ sub: 'uid' }, req)).rejects.toThrow(
      'Refresh token not provided in cookie',
    );
  });

  it('should throw if no valid refresh token found', async () => {
    (bcrypt.compareSync as ReturnType<typeof vi.fn>).mockReturnValue(false);
    const prisma = {
      user: { findUnique: vi.fn().mockResolvedValue({ id: 'uid' }) },
      refreshToken: { findMany: vi.fn().mockResolvedValue([]) },
    } as unknown as PrismaService;
    const strategy = new JwtRefreshStrategy(prisma);
    const req = {
      cookies: { refresh_token: 't' },
    } as unknown as FastifyRequest;
    await expect(strategy.validate({ sub: 'uid' }, req)).rejects.toThrow(
      'Refresh token invalid or expired',
    );
    (bcrypt.compareSync as ReturnType<typeof vi.fn>).mockReturnValue(true);
  });

  it('should throw if refresh token is expired', async () => {
    const prisma = {
      user: { findUnique: vi.fn().mockResolvedValue({ id: 'uid' }) },
      refreshToken: {
        findMany: vi.fn().mockResolvedValue([
          {
            token: 'hashed',
            expiresAt: new Date(Date.now() - 10000),
          },
        ]),
      },
    } as unknown as PrismaService;
    const strategy = new JwtRefreshStrategy(prisma);
    const req = {
      cookies: { refresh_token: 't' },
    } as unknown as FastifyRequest;
    await expect(strategy.validate({ sub: 'uid' }, req)).rejects.toThrow(
      'Refresh token invalid or expired',
    );
  });

  it('should return user and token on success', async () => {
    const user = { id: 'uid' };
    const prisma = {
      user: { findUnique: vi.fn().mockResolvedValue(user) },
      refreshToken: {
        findMany: vi.fn().mockResolvedValue([
          {
            token: 'hashed',
            expiresAt: new Date(Date.now() + 10000),
          },
        ]),
      },
    } as unknown as PrismaService;
    const strategy = new JwtRefreshStrategy(prisma);
    const req = {
      cookies: { refresh_token: 't' },
    } as unknown as FastifyRequest;
    const result = await strategy.validate({ sub: 'uid' }, req);
    expect(result).toEqual({ user, refreshToken: 't' });
  });
});
