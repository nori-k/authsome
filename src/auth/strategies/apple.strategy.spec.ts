import { describe, it, expect, vi } from 'vitest';
import { AppleStrategy } from './apple.strategy';
import type { AuthService } from '../services/auth.service';
import * as AppleProfileDtoModule from '../dto/apple-profile.dto';

describe('AppleStrategy', () => {
  it('should construct with env', () => {
    process.env.APPLE_PRIVATE_KEY = 'dummy';
    process.env.APPLE_CLIENT_ID = 'dummy';
    process.env.APPLE_TEAM_ID = 'dummy';
    process.env.APPLE_KEY_ID = 'dummy';
    process.env.BACKEND_URL = 'http://localhost';
    expect(() => new AppleStrategy({} as AuthService)).not.toThrow();
  });

  it('should call done with error if profile is invalid', () => {
    const done = vi.fn();
    const authService = {
      findOrCreateUserAndIdentity: vi.fn(),
    } as unknown as AuthService;
    const strategy = new AppleStrategy(authService);
    strategy.validate({ user: { id: 'u' } }, 'at', 'rt', {}, done);
    expect(done).toHaveBeenCalledWith(new Error('Invalid profile id'), false);
  });

  it('should call done with error if toAppleProfileDto throws', () => {
    const done = vi.fn();
    const authService = {
      findOrCreateUserAndIdentity: vi.fn(),
    } as unknown as AuthService;
    const strategy = new AppleStrategy(authService);
    const profile = { id: 'pid' };
    vi.spyOn(AppleProfileDtoModule, 'toAppleProfileDto').mockImplementation(
      () => {
        throw new Error('dto error');
      },
    );
    strategy.validate({ user: { id: 'u' } }, 'at', 'rt', profile, done);
    expect(done).toHaveBeenCalledWith(new Error('dto error'), false);
    vi.restoreAllMocks();
  });

  it('should call done with createdUser on success', async () => {
    const done = vi.fn();
    const createdUser = { id: 'u' };
    const findOrCreate = vi.fn().mockResolvedValue(createdUser);
    const authService = {
      findOrCreateUserAndIdentity: findOrCreate,
    } as unknown as AuthService;
    const strategy = new AppleStrategy(authService);
    const profile = { id: 'pid', email: 'e' };
    vi.spyOn(AppleProfileDtoModule, 'toAppleProfileDto').mockReturnValue({
      id: 'pid',
      email: 'e',
    });
    await new Promise<void>((resolve) => {
      strategy.validate(
        { user: { id: 'u' } },
        'at',
        'rt',
        profile,
        (...args) => {
          done(...args);
          resolve();
        },
      );
    });
    expect(done).toHaveBeenCalledWith(null, createdUser);
    vi.restoreAllMocks();
  });

  it('should call done with error if findOrCreateUserAndIdentity rejects', async () => {
    const done = vi.fn();
    const findOrCreate = vi.fn().mockRejectedValue(new Error('fail'));
    const authService = {
      findOrCreateUserAndIdentity: findOrCreate,
    } as unknown as AuthService;
    const strategy = new AppleStrategy(authService);
    const profile = { id: 'pid', email: 'e' };
    vi.spyOn(AppleProfileDtoModule, 'toAppleProfileDto').mockReturnValue({
      id: 'pid',
      email: 'e',
    });
    await new Promise<void>((resolve) => {
      strategy.validate(
        { user: { id: 'u' } },
        'at',
        'rt',
        profile,
        (...args) => {
          done(...args);
          resolve();
        },
      );
    });
    expect(done).toHaveBeenCalledWith(expect.any(Error), false);
    vi.restoreAllMocks();
  });
});
