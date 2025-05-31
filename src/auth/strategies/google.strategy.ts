import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy, Profile, VerifyCallback } from 'passport-google-oauth20';
import { ConfigService } from '@nestjs/config';
import { AuthService } from '../services/auth.service';
import {
  GoogleProfileDto,
  toGoogleProfileDto,
} from '../dto/google-profile.dto';
import type { ProviderType } from '@prisma/client';

function isProfile(obj: unknown): obj is Profile {
  if (typeof obj !== 'object' || obj === null) return false;
  const desc = Object.getOwnPropertyDescriptor(obj, 'id');
  return !!desc && typeof desc.value === 'string';
}

@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, 'google') {
  constructor(
    private readonly configService: ConfigService,
    private readonly _authService: AuthService,
  ) {
    super({
      clientID: configService.get<string>('GOOGLE_CLIENT_ID'),
      clientSecret: configService.get<string>('GOOGLE_CLIENT_SECRET'),
      callbackURL: `${configService.get<string>('BACKEND_URL')}/auth/google/callback`,
      scope: ['email', 'profile'],
      passReqToCallback: true,
    } as unknown as Record<string, unknown>);
  }

  /**
   * Google OAuth callback validation.
   * @param req Request object
   * @param accessToken OAuth access token
   * @param refreshToken OAuth refresh token
   * @param profile Google profile
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
    let googleProfile: GoogleProfileDto;
    try {
      googleProfile = toGoogleProfileDto(profile);
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
        'google' as ProviderType,
        googleProfile.id,
        googleProfile.email,
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
