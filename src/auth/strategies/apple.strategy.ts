import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy, Profile, VerifyCallback } from 'passport-apple';
import { AppleProfileDto, toAppleProfileDto } from '../dto/apple-profile.dto';
import { AuthService } from '../services/auth.service';
import type { ProviderType } from '@prisma/client';

// 型ガード: Profile型かどうか
function isProfile(obj: unknown): obj is Profile {
  if (typeof obj !== 'object' || obj === null) return false;
  const desc = Object.getOwnPropertyDescriptor(obj, 'id');
  return !!desc && typeof desc.value === 'string';
}

@Injectable()
export class AppleStrategy extends PassportStrategy(Strategy, 'apple') {
  constructor(
    private readonly _authService: AuthService, // 未使用警告回避
  ) {
    const privateKeyRaw = process.env.APPLE_PRIVATE_KEY;
    if (!privateKeyRaw) throw new Error('Missing APPLE_PRIVATE_KEY');
    const privateKeyString = privateKeyRaw.replace(/\\n/g, '\n');
    const clientID = process.env.APPLE_CLIENT_ID;
    if (!clientID) throw new Error('Missing APPLE_CLIENT_ID');
    const teamID = process.env.APPLE_TEAM_ID;
    if (!teamID) throw new Error('Missing APPLE_TEAM_ID');
    const keyID = process.env.APPLE_KEY_ID;
    if (!keyID) throw new Error('Missing APPLE_KEY_ID');
    const backendUrl = process.env.BACKEND_URL;
    if (!backendUrl) throw new Error('Missing BACKEND_URL');
    super({
      clientID,
      teamID,
      keyID,
      privateKeyString,
      callbackURL: `${backendUrl}/auth/apple/callback`,
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
    let appleProfile: AppleProfileDto;
    try {
      appleProfile = toAppleProfileDto(profile);
    } catch (e) {
      if (typeof done === 'function') {
        (done as (_err: Error | null, _user?: unknown) => void)(
          e instanceof Error ? e : new Error(String(e)),
          false,
        );
      }
      return;
    }
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
