import { describe, it, expect, vi } from 'vitest';
import { GoogleStrategy } from './google.strategy';
import type { AuthService } from '../services/auth.service';
import * as GoogleProfileDtoModule from '../dto/google-profile.dto';

describe('GoogleStrategy', () => {
  it('should construct with env', () => {
    expect(() => new GoogleStrategy({} as AuthService)).not.toThrow();
  });

  it('should call done with error if profile is invalid', () => {
    const done = vi.fn();
    const authService = {
      findOrCreateUserAndIdentity: vi.fn(),
    } as unknown as AuthService;
    const strategy = new GoogleStrategy(authService);
    strategy.validate({ user: { id: 'u' } }, 'at', 'rt', {}, done);
    expect(done).toHaveBeenCalledWith(new Error('Invalid profile id'), false);
  });

  it('should call done with error if toGoogleProfileDto throws', () => {
    const done = vi.fn();
    const authService = {
      findOrCreateUserAndIdentity: vi.fn(),
    } as unknown as AuthService;
    const strategy = new GoogleStrategy(authService);
    const profile = { id: 'pid', emails: [{ value: 'e' }] };
    vi.spyOn(GoogleProfileDtoModule, 'toGoogleProfileDto').mockImplementation(
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
    const strategy = new GoogleStrategy(authService);
    const profile = { id: 'pid', emails: [{ value: 'e' }] };
    vi.spyOn(GoogleProfileDtoModule, 'toGoogleProfileDto').mockReturnValue({
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
    const strategy = new GoogleStrategy(authService);
    const profile = { id: 'pid', emails: [{ value: 'e' }] };
    vi.spyOn(GoogleProfileDtoModule, 'toGoogleProfileDto').mockReturnValue({
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
