// bcryptjsを完全にモック化
import { vi } from 'vitest';
vi.mock('bcryptjs', () => ({
  hash: vi.fn(),
  compare: vi.fn(),
  compareSync: vi.fn(),
  hashSync: vi.fn(),
}));
import * as bcrypt from 'bcryptjs';

import { Test, type TestingModule } from '@nestjs/testing';
import { AuthService } from './auth.service';
import { PrismaService } from '../../prisma/prisma.service';
import { JwtService } from '@nestjs/jwt';
import type { AuthRegisterDto, AuthLoginDto } from '../dto/auth.dto';
import { PasskeyService } from './passkey.service';

// --- 依存サービスをprivateプロパティに直接注入 ---
describe('AuthService', () => {
  let service: AuthService;
  let prisma: PrismaService;
  let defaultUser: { id: string; email: string; password?: string };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        {
          provide: PrismaService,
          useValue: {
            user: {
              create: vi.fn(),
              findUnique: vi.fn(),
            },
            refreshToken: {
              create: vi.fn(),
              findMany: vi.fn(),
              delete: vi.fn(),
            },
            identity: {
              findMany: vi.fn(),
              findUnique: vi.fn(),
              count: vi.fn(),
              delete: vi.fn(),
              create: vi.fn(),
            },
          },
        },
        {
          provide: JwtService,
          useValue: {
            sign: vi.fn().mockReturnValue('jwt-token'),
          },
        },
        {
          provide: PasskeyService,
          useValue: {},
        },
      ],
    }).compile();
    service = module.get<AuthService>(AuthService);
    prisma = module.get<PrismaService>(PrismaService);
    // @ts-expect-error: テスト用にprivateへ直接代入
    service._prisma = prisma;
    // @ts-expect-error: テスト用にprivateへ直接代入
    service._jwtService = module.get<JwtService>(JwtService);
    defaultUser = {
      id: 'user1',
      email: 'test@example.com',
      password: 'hashedpw',
    };
    // Prismaメソッドを明示的にvi.fn()で再代入
    prisma.user.create = vi.fn();
    prisma.user.findUnique = vi.fn();
    prisma.refreshToken.create = vi.fn();
    prisma.refreshToken.findMany = vi.fn();
    prisma.refreshToken.delete = vi.fn();
    prisma.identity.findMany = vi.fn();
    prisma.identity.findUnique = vi.fn();
    prisma.identity.count = vi.fn();
    prisma.identity.delete = vi.fn();
    prisma.identity.create = vi.fn();
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('registerEmailPassword', () => {
    it('registers a new user and returns id/email', async () => {
      const dto: AuthRegisterDto = {
        email: defaultUser.email,
        password: 'Password1',
      };
      (bcrypt.hash as ReturnType<typeof vi.fn>).mockResolvedValue('hashedpw');
      prisma.user.create = vi.fn().mockResolvedValue({
        id: defaultUser.id,
        email: defaultUser.email,
      });
      const result = await service.registerEmailPassword(dto);
      expect(result).toEqual({
        id: defaultUser.id,
        email: defaultUser.email,
      });
      const calls = (prisma.user.create as ReturnType<typeof vi.fn>).mock.calls;
      if (
        Array.isArray(calls) &&
        calls.length > 0 &&
        Array.isArray(calls[0]) &&
        calls[0].length > 0
      ) {
        expect(calls[0][0]).toMatchObject({
          data: { email: defaultUser.email, password: 'hashedpw' },
        });
      }
    });
  });

  describe('loginEmailPassword', () => {
    it('logs in with correct password', async () => {
      const dto: AuthLoginDto = {
        email: defaultUser.email,
        password: 'Password1',
      };
      prisma.user.findUnique = vi.fn().mockResolvedValue(defaultUser);
      (bcrypt.compare as ReturnType<typeof vi.fn>).mockResolvedValue(true);
      prisma.refreshToken.create = vi.fn().mockResolvedValue({});
      const result = await service.loginEmailPassword(dto);
      expect(result).toEqual({
        accessToken: 'jwt-token',
        refreshToken: 'jwt-token',
        userId: defaultUser.id,
        email: defaultUser.email, // emailを追加
      });
    });
    it('throws if password is wrong', async () => {
      const dto: AuthLoginDto = {
        email: defaultUser.email,
        password: 'wrong',
      };
      prisma.user.findUnique = vi.fn().mockResolvedValue(defaultUser);
      (bcrypt.compare as ReturnType<typeof vi.fn>).mockResolvedValue(false);
      await expect(service.loginEmailPassword(dto)).rejects.toThrow(
        'Invalid credentials',
      );
    });
    it('throws if user not found', async () => {
      const dto: AuthLoginDto = {
        email: 'notfound@example.com',
        password: 'Password1',
      };
      prisma.user.findUnique = vi.fn().mockResolvedValue(null);
      await expect(service.loginEmailPassword(dto)).rejects.toThrow(
        'Invalid credentials',
      );
    });
  });

  describe('refreshTokens', () => {
    it('refreshes tokens if old refresh token is valid', async () => {
      prisma.refreshToken.findMany = vi
        .fn()
        .mockResolvedValue([
          { id: 'rt1', token: 'hashed-old', userId: defaultUser.id },
        ]);
      (bcrypt.compareSync as ReturnType<typeof vi.fn>).mockReturnValue(true);
      prisma.refreshToken.delete = vi.fn().mockResolvedValue({});
      prisma.refreshToken.create = vi.fn().mockResolvedValue({});
      const result = await service.refreshTokens(defaultUser.id, 'oldtoken');
      expect(result).toEqual({
        accessToken: 'jwt-token',
        refreshToken: 'jwt-token',
        userId: defaultUser.id,
      });
    });
    it('throws if old refresh token is not found', async () => {
      prisma.refreshToken.findMany = vi
        .fn()
        .mockResolvedValue([
          { id: 'rt1', token: 'hashed-other', userId: defaultUser.id },
        ]);
      (bcrypt.compareSync as ReturnType<typeof vi.fn>).mockReturnValue(false);
      await expect(
        service.refreshTokens(defaultUser.id, 'badtoken'),
      ).rejects.toThrow('Refresh token not found or already invalidated.');
    });
  });

  describe('logout', () => {
    it('deletes refresh token if found', async () => {
      prisma.refreshToken.findMany = vi
        .fn()
        .mockResolvedValue([
          { id: 'rt1', token: 'hashed-token', userId: defaultUser.id },
        ]);
      (bcrypt.compareSync as ReturnType<typeof vi.fn>).mockReturnValue(true);
      prisma.refreshToken.delete = vi.fn().mockResolvedValue({});
      await expect(
        service.logout(defaultUser.id, 'token'),
      ).resolves.toBeUndefined();
    });
    it('does nothing if token not found', async () => {
      prisma.refreshToken.findMany = vi
        .fn()
        .mockResolvedValue([
          { id: 'rt1', token: 'hashed-token', userId: defaultUser.id },
        ]);
      (bcrypt.compareSync as ReturnType<typeof vi.fn>).mockReturnValue(false);
      await expect(
        service.logout(defaultUser.id, 'notfound'),
      ).resolves.toBeUndefined();
    });
  });

  describe('getProfile', () => {
    it('returns user if found', async () => {
      prisma.user.findUnique = vi.fn().mockResolvedValue(defaultUser);
      const result = await service.getProfile(defaultUser.id);
      expect(result).toEqual({
        id: defaultUser.id,
        email: defaultUser.email,
        password: 'hashedpw',
      });
    });
    it('returns null if user not found', async () => {
      prisma.user.findUnique = vi.fn().mockResolvedValue(null);
      const result = await service.getProfile('nouser');
      expect(result).toBeNull();
    });
  });

  describe('generateTokens', () => {
    it('returns access and refresh tokens', () => {
      const jwt = service['_jwtService'] as unknown as { sign: typeof vi.fn };
      if (jwt && typeof jwt.sign === 'function') {
        jwt.sign = vi.fn().mockReturnValue('jwt-token');
      }
      const result = service.generateTokens(defaultUser.id);
      expect(result).toEqual({
        accessToken: 'jwt-token',
        refreshToken: 'jwt-token',
      });
    });
  });

  describe('getIdentities', () => {
    it('returns identities for user', async () => {
      prisma.identity.findMany = vi.fn().mockResolvedValue([
        {
          id: 'id1',
          provider: 'google',
          email: 'a@example.com',
          createdAt: new Date(),
        },
      ]);
      const result = await service.getIdentities(defaultUser.id);
      expect(result.length).toBe(1);
      expect(result[0].provider).toBe('google');
    });
  });

  describe('deleteIdentity', () => {
    it('deletes identity if found and not last', async () => {
      prisma.identity.findUnique = vi.fn().mockResolvedValue({
        id: 'id1',
        userId: defaultUser.id,
      });
      prisma.identity.count = vi.fn().mockResolvedValue(2);
      prisma.identity.delete = vi.fn().mockResolvedValue({});
      await expect(
        service.deleteIdentity(defaultUser.id, 'id1'),
      ).resolves.toBeUndefined();
    });
    it('throws if identity not found or not owned', async () => {
      prisma.identity.findUnique = vi.fn().mockResolvedValue(null);
      await expect(
        service.deleteIdentity(defaultUser.id, 'id1'),
      ).rejects.toThrow('Identity not found or not owned by user');
    });
    it('throws if last identity', async () => {
      prisma.identity.findUnique = vi.fn().mockResolvedValue({
        id: 'id1',
        userId: defaultUser.id,
      });
      prisma.identity.count = vi.fn().mockResolvedValue(1);
      await expect(
        service.deleteIdentity(defaultUser.id, 'id1'),
      ).rejects.toThrow(
        'Cannot delete the last identity. Please add another login method first.',
      );
    });
  });

  describe('findOrCreateUserAndIdentity', () => {
    it('returns user if identity exists', async () => {
      prisma.identity.findUnique = vi.fn().mockResolvedValue({
        user: { id: defaultUser.id },
      });
      const result = await service.findOrCreateUserAndIdentity(
        'google',
        'pid',
        'a@example.com',
        null,
      );
      expect(result).toEqual({ id: defaultUser.id });
    });
    it('creates identity for currentUserId', async () => {
      prisma.identity.findUnique = vi.fn().mockResolvedValue(null);
      prisma.user.findUnique = vi.fn().mockResolvedValueOnce({
        id: 'user2',
        email: 'b@example.com',
      });
      prisma.identity.create = vi.fn().mockResolvedValue({});
      const result = await service.findOrCreateUserAndIdentity(
        'google',
        'pid',
        'b@example.com',
        'user2',
      );
      expect(result).toEqual({ id: 'user2', email: 'b@example.com' });
    });
    it('creates identity for email', async () => {
      prisma.identity.findUnique = vi.fn().mockResolvedValue(null);
      prisma.user.findUnique = vi.fn().mockResolvedValueOnce(null);
      prisma.user.findUnique = vi.fn().mockResolvedValueOnce(null);
      prisma.user.create = vi.fn().mockResolvedValue({
        id: 'user3',
        email: 'c@example.com',
      });
      prisma.identity.create = vi.fn().mockResolvedValue({});
      const result = await service.findOrCreateUserAndIdentity(
        'google',
        'pid',
        'c@example.com',
        null,
      );
      expect(result).toEqual({ id: 'user3', email: 'c@example.com' });
    });
    it('creates new user and identity if none found', async () => {
      prisma.identity.findUnique = vi.fn().mockResolvedValue(null);
      prisma.user.findUnique = vi.fn().mockResolvedValueOnce(null);
      prisma.user.findUnique = vi.fn().mockResolvedValueOnce(null);
      prisma.user.create = vi.fn().mockResolvedValue({
        id: 'user4',
        email: 'd@example.com',
      });
      prisma.identity.create = vi.fn().mockResolvedValue({});
      const result = await service.findOrCreateUserAndIdentity(
        'google',
        'pid',
        'd@example.com',
        null,
      );
      expect(result).toEqual({ id: 'user4', email: 'd@example.com' });
    });
  });
});
