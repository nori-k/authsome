import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy, Profile, VerifyCallback } from 'passport-apple';
import { ConfigService } from '@nestjs/config';
import { AppleProfileDto, toAppleProfileDto } from '../dto/apple-profile.dto';
import { AuthService } from '../services/auth.service';
import type { ProviderType } from '@prisma/client';

function getConfigString(config: ConfigService, key: string): string {
  const value = config.get<string>(key);
  if (!value) throw new Error(`Missing config: ${key}`);
  return value;
}

// 型ガード: Profile型かどうか
function isProfile(obj: unknown): obj is Profile {
  if (typeof obj !== 'object' || obj === null) return false;
  const desc = Object.getOwnPropertyDescriptor(obj, 'id');
  return !!desc && typeof desc.value === 'string';
}

@Injectable()
export class AppleStrategy extends PassportStrategy(Strategy, 'apple') {
  constructor(
    private readonly configService: ConfigService,
    private readonly _authService: AuthService, // 未使用警告回避
  ) {
    const privateKeyRaw = getConfigString(configService, 'APPLE_PRIVATE_KEY');
    const privateKeyString = privateKeyRaw.replace(/\\n/g, '\n');
    super({
      clientID: getConfigString(configService, 'APPLE_CLIENT_ID'),
      teamID: getConfigString(configService, 'APPLE_TEAM_ID'),
      keyID: getConfigString(configService, 'APPLE_KEY_ID'),
      privateKeyString,
      callbackURL: `${getConfigString(configService, 'BACKEND_URL')}/auth/apple/callback`,
      scope: ['name', 'email'],
      passReqToCallback: true,
    } as unknown as Record<string, unknown>);
  }

  /**
   * Apple OAuth callback validation.
   * @param req Request object
   * @param accessToken OAuth access token
   * @param refreshToken OAuth refresh token
   * @param profile Apple profile
   * @param done Passport callback
   */
  validate(
    req: { user?: { id?: string } },
    accessToken: string,
    refreshToken: string,
    profile: unknown,
    done: VerifyCallback,
  ): void {
    if (!isProfile(profile)) {
      if (typeof done === 'function') {
        (done as (_err: Error | null, _user?: unknown) => void)(
          new Error('Invalid profile id'),
          false,
        );
      }
      return;
    }
    const appleProfile: AppleProfileDto = toAppleProfileDto(profile);
    const currentUserId = typeof req.user?.id === 'string' ? req.user.id : null;
    this._authService
      .findOrCreateUserAndIdentity(
        'apple' as ProviderType,
        (profile as { id: string }).id,
        appleProfile.email,
        currentUserId,
      )
      .then((createdUser) => {
        if (typeof done === 'function') {
          (done as (_err: Error | null, _user?: unknown) => void)(
            null,
            createdUser,
          );
        }
      })
      .catch((error: unknown) => {
        if (typeof done === 'function') {
          (done as (_err: Error | null, _user?: unknown) => void)(
            error instanceof Error ? error : new Error(String(error)),
            false,
          );
        }
      });
  }
}
