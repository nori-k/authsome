import {
  Injectable,
  UnauthorizedException,
  ConflictException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from '../../prisma/prisma.service';
import type { User, ProviderType } from '@prisma/client';
import * as bcrypt from 'bcryptjs';
import { AuthRegisterDto, AuthLoginDto } from '../dto/auth.dto';
import { PasskeyService } from './passkey.service';

/**
 * AuthService handles all authentication logic (email/password, OAuth, tokens).
 * - No business logic in controllers.
 * - All methods are strictly typed.
 */
@Injectable()
export class AuthService {
  constructor(
    private readonly _prisma: PrismaService,
    private readonly _jwtService: JwtService,
    private readonly _passkeyService: PasskeyService,
  ) {}

  /**
   * Register a new user with email and password.
   * @param dto Registration DTO
   * @returns User id and email
   */
  async registerEmailPassword(
    dto: AuthRegisterDto,
  ): Promise<{ id: string; email: string | null }> {
    const hashedPassword = await bcrypt.hash(dto.password, 10);
    try {
      const user = await this._prisma.user.create({
        data: {
          email: dto.email,
          password: hashedPassword,
        },
      });
      return { id: user.id, email: user.email };
    } catch (error) {
      const err = error as { code?: string; meta?: { target?: string[] } };
      if (err.code === 'P2002' && err.meta?.target?.includes('email')) {
        throw new ConflictException('This email is already registered.');
      }
      throw error;
    }
  }

  /**
   * Login with email and password.
   * @param dto Login DTO
   * @returns Access/refresh tokens and userId
   * @throws UnauthorizedException
   */
  async loginEmailPassword(dto: AuthLoginDto): Promise<{
    accessToken: string;
    refreshToken: string;
    userId: string;
    email: string | null;
  }> {
    const user = await this._prisma.user.findUnique({
      where: { email: dto.email },
    });
    if (!user || typeof user.password !== 'string' || user.password === '') {
      throw new UnauthorizedException('Invalid credentials');
    }
    const isPasswordValid = await bcrypt.compare(dto.password, user.password);
    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid credentials');
    }
    const accessToken = this._jwtService.sign(
      { sub: user.id, email: user.email },
      { expiresIn: '15m' },
    );
    const refreshToken = this._jwtService.sign(
      { sub: user.id, email: user.email },
      { expiresIn: '7d' },
    );
    const expiresAt = new Date(Date.now() + 1000 * 60 * 60 * 24 * 7);
    await this._prisma.refreshToken.create({
      data: {
        userId: user.id,
        token: bcrypt.hashSync(refreshToken, 10),
        expiresAt,
      },
    });
    return { accessToken, refreshToken, userId: user.id, email: user.email };
  }

  /**
   * Generate new access/refresh tokens for a user.
   * @param userId User id
   * @returns Tokens
   */
  generateTokens(userId: string): {
    accessToken: string;
    refreshToken: string;
  } {
    const accessToken = this._jwtService.sign(
      { sub: userId },
      { expiresIn: '15m' },
    );
    const refreshToken = this._jwtService.sign(
      { sub: userId },
      { expiresIn: '7d' },
    );
    return { accessToken, refreshToken };
  }

  /**
   * Refresh tokens for a user, invalidating the old refresh token.
   * @param userId User id
   * @param oldRefreshToken Old refresh token
   * @returns New tokens and userId
   * @throws UnauthorizedException
   */
  async refreshTokens(
    userId: string,
    oldRefreshToken: string,
  ): Promise<{ accessToken: string; refreshToken: string; userId: string }> {
    const storedTokens = await this._prisma.refreshToken.findMany({
      where: { userId },
    });
    const targetToken = storedTokens.find((token) =>
      bcrypt.compareSync(oldRefreshToken, token.token),
    );
    if (!targetToken) {
      throw new UnauthorizedException(
        'Refresh token not found or already invalidated.',
      );
    }
    await this._prisma.refreshToken.delete({
      where: { id: targetToken.id },
    });
    const { accessToken, refreshToken } = this.generateTokens(userId);
    const expiresAt = new Date(Date.now() + 1000 * 60 * 60 * 24 * 7);
    await this._prisma.refreshToken.create({
      data: {
        userId,
        token: bcrypt.hashSync(refreshToken, 10),
        expiresAt,
      },
    });
    return { accessToken, refreshToken, userId };
  }

  /**
   * Find or create a user and identity for OAuth providers.
   * @param provider ProviderType enum (e.g. 'google', 'apple')
   * @param providerId Provider user id
   * @param email Email address
   * @param currentUserId Optional current user id (for linking)
   * @returns User
   */
  async findOrCreateUserAndIdentity(
    provider: ProviderType,
    providerId: string,
    email: string | null,
    currentUserId?: string | null,
  ): Promise<User> {
    const identity = await this._prisma.identity.findUnique({
      where: { provider_providerId: { provider, providerId } },
      include: { user: true },
    });
    if (identity && identity.user) return identity.user;

    let user: User | null = null;
    if (typeof currentUserId === 'string' && currentUserId) {
      user = await this._prisma.user.findUnique({
        where: { id: currentUserId },
      });
    }
    if (!user && typeof email === 'string' && email !== '') {
      user = await this._prisma.user.findUnique({
        where: { email },
      });
    }
    user ??= await this._prisma.user.create({ data: { email } });

    await this._prisma.identity.create({
      data: {
        userId: user.id,
        provider,
        providerId,
        email,
      },
    });
    return user;
  }

  // --- ログアウト ---
  async logout(userId: string, refreshToken: string): Promise<void> {
    const storedTokens = await this._prisma.refreshToken.findMany({
      where: { userId },
    });
    const targetToken = storedTokens.find((token) =>
      bcrypt.compareSync(refreshToken, token.token),
    );
    if (targetToken) {
      await this._prisma.refreshToken.delete({
        where: { id: targetToken.id },
      });
    }
  }

  // --- プロファイル取得 ---
  async getProfile(userId: string): Promise<User | null> {
    return this._prisma.user.findUnique({
      where: { id: userId },
    });
  }

  // --- Identities管理 ---
  async getIdentities(userId: string): Promise<
    Array<{
      id: string;
      provider: string;
      email: string | null;
      createdAt: Date;
    }>
  > {
    return this._prisma.identity.findMany({
      where: { userId },
      select: { id: true, provider: true, email: true, createdAt: true },
    });
  }

  async deleteIdentity(userId: string, identityId: string): Promise<void> {
    const identity = await this._prisma.identity.findUnique({
      where: { id: identityId },
    });
    if (!identity || identity.userId !== userId) {
      throw new UnauthorizedException(
        'Identity not found or not owned by user',
      );
    }
    const userIdentitiesCount = await this._prisma.identity.count({
      where: { userId },
    });
    if (userIdentitiesCount <= 1) {
      throw new Error(
        'Cannot delete the last identity. Please add another login method first.',
      );
    }
    await this._prisma.identity.delete({
      where: { id: identityId },
    });
  }
}
