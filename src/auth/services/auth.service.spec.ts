import { Test, type TestingModule } from '@nestjs/testing';
import { AuthService } from './auth.service';
import { PrismaService } from '../../prisma/prisma.service';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcryptjs';
import type { AuthRegisterDto, AuthLoginDto } from '../dto/auth.dto';
import { PasskeyService } from './passkey.service';

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
              create: jest.fn(),
              findUnique: jest.fn(),
            },
            refreshToken: {
              create: jest.fn(),
              findMany: jest.fn(),
              delete: jest.fn(),
            },
            identity: {
              findMany: jest.fn(),
              findUnique: jest.fn(),
              count: jest.fn(),
              delete: jest.fn(),
              create: jest.fn(),
            },
          },
        },
        {
          provide: JwtService,
          useValue: {
            sign: jest.fn().mockReturnValue('jwt-token'),
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
    defaultUser = {
      id: 'user1',
      email: 'test@example.com',
      password: 'hashedpw',
    };
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
      jest.spyOn(bcrypt, 'hash').mockResolvedValue('hashedpw' as never);
      (prisma.user.create as jest.Mock).mockResolvedValue({
        id: defaultUser.id,
        email: defaultUser.email,
      });
      const result = await service.registerEmailPassword(dto);
      expect(result).toEqual({
        id: defaultUser.id,
        email: defaultUser.email,
      });
      const calls = (prisma.user.create as jest.Mock).mock.calls;
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
      (prisma.user.findUnique as jest.Mock).mockResolvedValue(defaultUser);
      jest.spyOn(bcrypt, 'compare').mockResolvedValue(true as never);
      (prisma.refreshToken.create as jest.Mock).mockResolvedValue({});
      const result = await service.loginEmailPassword(dto);
      expect(result).toEqual({
        accessToken: 'jwt-token',
        refreshToken: 'jwt-token',
        userId: defaultUser.id,
      });
    });
    it('throws if password is wrong', async () => {
      const dto: AuthLoginDto = {
        email: defaultUser.email,
        password: 'wrong',
      };
      (prisma.user.findUnique as jest.Mock).mockResolvedValue(defaultUser);
      jest.spyOn(bcrypt, 'compare').mockResolvedValue(false as never);
      await expect(service.loginEmailPassword(dto)).rejects.toThrow(
        'Invalid credentials',
      );
    });
    it('throws if user not found', async () => {
      const dto: AuthLoginDto = {
        email: 'notfound@example.com',
        password: 'Password1',
      };
      (prisma.user.findUnique as jest.Mock).mockResolvedValue(null);
      await expect(service.loginEmailPassword(dto)).rejects.toThrow(
        'Invalid credentials',
      );
    });
  });

  describe('refreshTokens', () => {
    it('refreshes tokens if old refresh token is valid', async () => {
      (prisma.refreshToken.findMany as jest.Mock).mockResolvedValue([
        { id: 'rt1', token: 'hashed-old', userId: defaultUser.id },
      ]);
      jest.spyOn(bcrypt, 'compareSync').mockReturnValue(true);
      (prisma.refreshToken.delete as jest.Mock).mockResolvedValue({});
      (prisma.refreshToken.create as jest.Mock).mockResolvedValue({});
      const result = await service.refreshTokens(defaultUser.id, 'oldtoken');
      expect(result).toEqual({
        accessToken: 'jwt-token',
        refreshToken: 'jwt-token',
        userId: defaultUser.id,
      });
    });
    it('throws if old refresh token is not found', async () => {
      (prisma.refreshToken.findMany as jest.Mock).mockResolvedValue([
        { id: 'rt1', token: 'hashed-other', userId: defaultUser.id },
      ]);
      jest.spyOn(bcrypt, 'compareSync').mockReturnValue(false);
      await expect(
        service.refreshTokens(defaultUser.id, 'badtoken'),
      ).rejects.toThrow('Refresh token not found or already invalidated.');
    });
  });

  describe('logout', () => {
    it('deletes refresh token if found', async () => {
      (prisma.refreshToken.findMany as jest.Mock).mockResolvedValue([
        { id: 'rt1', token: 'hashed-token', userId: defaultUser.id },
      ]);
      jest.spyOn(bcrypt, 'compareSync').mockReturnValue(true);
      (prisma.refreshToken.delete as jest.Mock).mockResolvedValue({});
      await expect(
        service.logout(defaultUser.id, 'token'),
      ).resolves.toBeUndefined();
    });
    it('does nothing if token not found', async () => {
      (prisma.refreshToken.findMany as jest.Mock).mockResolvedValue([
        { id: 'rt1', token: 'hashed-token', userId: defaultUser.id },
      ]);
      jest.spyOn(bcrypt, 'compareSync').mockReturnValue(false);
      await expect(
        service.logout(defaultUser.id, 'notfound'),
      ).resolves.toBeUndefined();
    });
  });

  describe('getProfile', () => {
    it('returns user if found', async () => {
      (prisma.user.findUnique as jest.Mock).mockResolvedValue(defaultUser);
      const result = await service.getProfile(defaultUser.id);
      expect(result).toEqual({
        id: defaultUser.id,
        email: defaultUser.email,
        password: 'hashedpw',
      });
    });
    it('returns null if user not found', async () => {
      (prisma.user.findUnique as jest.Mock).mockResolvedValue(null);
      const result = await service.getProfile('nouser');
      expect(result).toBeNull();
    });
  });

  describe('generateTokens', () => {
    it('returns access and refresh tokens', () => {
      const jwt = service['_jwtService'] as unknown as { sign: jest.Mock };
      if (jwt && typeof jwt.sign === 'function') {
        jwt.sign = jest.fn().mockReturnValue('jwt-token');
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
      (prisma.identity.findMany as jest.Mock).mockResolvedValue([
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
      (prisma.identity.findUnique as jest.Mock).mockResolvedValue({
        id: 'id1',
        userId: defaultUser.id,
      });
      (prisma.identity.count as jest.Mock).mockResolvedValue(2);
      (prisma.identity.delete as jest.Mock).mockResolvedValue({});
      await expect(
        service.deleteIdentity(defaultUser.id, 'id1'),
      ).resolves.toBeUndefined();
    });
    it('throws if identity not found or not owned', async () => {
      (prisma.identity.findUnique as jest.Mock).mockResolvedValue(null);
      await expect(
        service.deleteIdentity(defaultUser.id, 'id1'),
      ).rejects.toThrow('Identity not found or not owned by user');
    });
    it('throws if last identity', async () => {
      (prisma.identity.findUnique as jest.Mock).mockResolvedValue({
        id: 'id1',
        userId: defaultUser.id,
      });
      (prisma.identity.count as jest.Mock).mockResolvedValue(1);
      await expect(
        service.deleteIdentity(defaultUser.id, 'id1'),
      ).rejects.toThrow(
        'Cannot delete the last identity. Please add another login method first.',
      );
    });
  });

  describe('findOrCreateUserAndIdentity', () => {
    it('returns user if identity exists', async () => {
      (prisma.identity.findUnique as jest.Mock).mockResolvedValue({
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
      (prisma.identity.findUnique as jest.Mock).mockResolvedValue(null);
      (prisma.user.findUnique as jest.Mock).mockResolvedValueOnce({
        id: 'user2',
        email: 'b@example.com',
      });
      (prisma.identity.create as jest.Mock).mockResolvedValue({});
      const result = await service.findOrCreateUserAndIdentity(
        'google',
        'pid',
        'b@example.com',
        'user2',
      );
      expect(result).toEqual({ id: 'user2', email: 'b@example.com' });
    });
    it('creates identity for email', async () => {
      (prisma.identity.findUnique as jest.Mock).mockResolvedValue(null);
      (prisma.user.findUnique as jest.Mock)
        .mockResolvedValueOnce(null)
        .mockResolvedValueOnce(null);
      (prisma.user.create as jest.Mock).mockResolvedValue({
        id: 'user3',
        email: 'c@example.com',
      });
      (prisma.identity.create as jest.Mock).mockResolvedValue({});
      const result = await service.findOrCreateUserAndIdentity(
        'google',
        'pid',
        'c@example.com',
        null,
      );
      expect(result).toEqual({ id: 'user3', email: 'c@example.com' });
    });
    it('creates new user and identity if none found', async () => {
      (prisma.identity.findUnique as jest.Mock).mockResolvedValue(null);
      (prisma.user.findUnique as jest.Mock)
        .mockResolvedValueOnce(null)
        .mockResolvedValueOnce(null);
      (prisma.user.create as jest.Mock).mockResolvedValue({
        id: 'user4',
        email: 'd@example.com',
      });
      (prisma.identity.create as jest.Mock).mockResolvedValue({});
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
