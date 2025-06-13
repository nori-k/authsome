import { JwtAccessStrategy } from './jwt-access.strategy';
import type { ConfigService } from '@nestjs/config';
import type { PrismaService } from '../../prisma/prisma.service';

describe('JwtAccessStrategy', () => {
  // 型安全なConfigServiceモック
  const DummyConfigService = {
    get: () => 'test-secret',
  } as unknown as ConfigService;
  const DummyPrismaService = {} as PrismaService;

  it('should validate payload with sub', () => {
    const strategy = new JwtAccessStrategy(
      DummyConfigService,
      DummyPrismaService,
    );
    const payload = { sub: 'user-id' };
    expect(strategy.validate(payload)).toEqual({ id: 'user-id' });
  });

  it('should throw if payload.sub is missing', () => {
    const strategy = new JwtAccessStrategy(
      DummyConfigService,
      DummyPrismaService,
    );
    expect(() => strategy.validate({} as { sub: string })).toThrowError();
  });

  it('should throw if payload is null', () => {
    const strategy = new JwtAccessStrategy(
      DummyConfigService,
      DummyPrismaService,
    );
    expect(() =>
      strategy.validate(null as unknown as { sub: string }),
    ).toThrowError();
  });

  it('should throw if payload is undefined', () => {
    const strategy = new JwtAccessStrategy(
      DummyConfigService,
      DummyPrismaService,
    );
    expect(() =>
      strategy.validate(undefined as unknown as { sub: string }),
    ).toThrowError();
  });

  it('should throw if payload.sub is not a string', () => {
    const strategy = new JwtAccessStrategy(
      DummyConfigService,
      DummyPrismaService,
    );
    expect(() =>
      strategy.validate({ sub: 123 } as unknown as { sub: string }),
    ).toThrowError();
  });
});
