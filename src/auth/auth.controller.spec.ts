import { vi } from 'vitest';
import { Test, type TestingModule } from '@nestjs/testing';
import { AuthController } from './auth.controller';
import { AuthService } from './services/auth.service';
import { PasskeyService } from './services/passkey.service';
import type {
  AuthRegisterDto,
  AuthLoginDto,
  PasskeyRegisterFinishDto,
  PasskeyLoginFinishDto,
} from './dto/auth.dto';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { JwtModule } from '@nestjs/jwt';

// テスト用型定義（interfaceで）
interface TestVerifiedRegistrationResponse {
  verified: boolean;
  registrationInfo: {
    credential: { id: string; publicKey: Buffer; counter: number };
    fmt: string;
    aaguid: string;
  };
}
interface TestPublicKeyCredentialCreationOptionsJSON {
  rp: { name: string; id: string };
  user: { id: string; name: string; displayName: string };
  challenge: string;
  pubKeyCredParams: unknown[];
  timeout: number;
}
import type { WebAuthnCredential, User } from '@prisma/client';

// --- Vitest Mocked Type Helper ---
type Mocked<T> = {
  [K in keyof T]: T[K] extends (..._args: unknown[]) => unknown
    ? ReturnType<typeof vi.fn> & T[K]
    : T[K];
};

describe('AuthController', () => {
  let controller: AuthController;
  let authService: Mocked<AuthService>;
  let passkeyService: Mocked<PasskeyService>;
  let reply: Partial<FastifyReply>;

  function createRequestMock(
    user: Partial<User>,
    cookies: Record<string, string> = {},
  ): FastifyRequest {
    return {
      user,
      cookies,
      id: '',
      params: {},
      raw: {},
      query: {},
      log: { info: () => {}, error: () => {}, warn: () => {}, debug: () => {} },
      body: {},
      headers: {},
      ip: '',
      ips: [],
      method: 'GET',
      url: '',
      hostname: '',
      protocol: 'http',
      connection: {},
      socket: {},
      get: () => '',
    } as unknown as FastifyRequest;
  }

  beforeEach(async () => {
    authService = {
      registerEmailPassword: vi.fn(),
      loginEmailPassword: vi.fn(),
      generateTokens: vi.fn(),
      refreshTokens: vi.fn(),
      logout: vi.fn(),
      getIdentities: vi.fn(),
      deleteIdentity: vi.fn(),
      findOrCreateUserAndIdentity: vi.fn(),
      getProfile: vi.fn(),
    } as unknown as Mocked<AuthService>;
    passkeyService = {
      generatePasskeyRegistrationOptions: vi.fn(),
      verifyPasskeyRegistration: vi.fn(),
      verifyPasskeyAuthentication: vi.fn(),
      getPasskeyCredentials: vi.fn(),
      deletePasskeyCredential: vi.fn(),
    } as unknown as Mocked<PasskeyService>;
    reply = {
      setCookie: vi.fn(),
      clearCookie: vi.fn(),
      redirect: vi.fn(),
    };
    const module: TestingModule = await Test.createTestingModule({
      imports: [JwtModule.register({ secret: 'test' })],
      controllers: [AuthController],
      providers: [
        { provide: AuthService, useValue: authService },
        { provide: PasskeyService, useValue: passkeyService },
      ],
    }).compile();
    controller = module.get<AuthController>(AuthController);
    // --- 依存サービスをコントローラのprivateプロパティに直接注入 ---
    // @ts-expect-error: テスト用にprivateへ直接代入
    controller._authService = authService;
    // @ts-expect-error: テスト用にprivateへ直接代入
    controller._passkeyService = passkeyService;
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  describe('registerEmailPassword', () => {
    it('should call AuthService and return user', async () => {
      const dto: AuthRegisterDto = {
        email: 'a@b.com',
        password: 'pw',
      };
      const user = {
        id: '1',
        email: 'a@b.com',
      };
      authService.registerEmailPassword.mockResolvedValue(user);
      await expect(controller.registerEmailPassword(dto)).resolves.toEqual({
        id: '1',
        email: 'a@b.com',
      });
      expect(authService.registerEmailPassword.mock.calls[0][0]).toEqual({
        email: 'a@b.com',
        password: 'pw',
      });
    });
  });

  describe('loginEmailPassword', () => {
    it('should set cookies and return tokens', async () => {
      const dto: AuthLoginDto = {
        email: 'a@b.com',
        password: 'pw',
      };
      const result = {
        accessToken: 'a',
        refreshToken: 'r',
        userId: 'u',
        email: 'a@b.com', // emailを追加
      };
      authService.loginEmailPassword.mockResolvedValue(result);
      await expect(
        controller.loginEmailPassword(dto, reply as FastifyReply),
      ).resolves.toEqual(result);
      expect(authService.loginEmailPassword.mock.calls[0][0]).toEqual({
        email: 'a@b.com',
        password: 'pw',
      });
      expect(reply.setCookie).toBeCalledTimes(2);
    });
  });

  describe('refreshTokens', () => {
    it('should refresh tokens and set cookies', async () => {
      const request = createRequestMock({ id: 'u' }, { refresh_token: 'old' });
      const result = {
        accessToken: 'a',
        refreshToken: 'r',
        userId: 'u',
      };
      authService.refreshTokens.mockResolvedValue(result);
      await expect(
        controller.refreshTokens(request, reply as FastifyReply),
      ).resolves.toMatchObject({
        accessToken: 'a',
        refreshToken: 'r',
        userId: 'u',
      });
      expect(authService.refreshTokens.mock.calls[0][0]).toBe('u');
      expect(authService.refreshTokens.mock.calls[0][1]).toBe('old');
      expect(reply.setCookie).toBeCalledTimes(2);
    });
  });

  describe('logout', () => {
    it('should clear cookies and call logout', async () => {
      const request = createRequestMock({ id: 'u' }, { refresh_token: 'r' });
      authService.logout.mockResolvedValue(undefined);
      await expect(
        controller.logout(request, reply as FastifyReply),
      ).resolves.toEqual({
        message: 'Logged out successfully!',
      });
      expect(authService.logout.mock.calls[0][0]).toBe('u');
      expect(authService.logout.mock.calls[0][1]).toBe('r');
      expect(reply.clearCookie).toBeCalledTimes(2);
    });
  });

  describe('getProfile', () => {
    it('should return user from request', async () => {
      const user: User = {
        id: 'u',
        email: 'a@b.com',
        password: '',
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      const request = createRequestMock(user);
      authService.getProfile.mockResolvedValue(user);
      // getProfileは {id, email} だけ返すので、期待値も合わせる
      await expect(controller.getProfile(request)).resolves.toEqual({
        id: user.id,
        email: user.email,
      });
    });
  });

  describe('startPasskeyRegistration', () => {
    it('should call PasskeyService', async () => {
      const user: User = {
        id: 'u',
        email: 'a@b.com',
        password: '',
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      const request = createRequestMock(user);
      const options: TestPublicKeyCredentialCreationOptionsJSON = {
        rp: { name: 'authsome', id: 'localhost' },
        user: { id: 'u', name: 'a@b.com', displayName: 'a@b.com' },
        challenge: 'challenge',
        pubKeyCredParams: [],
        timeout: 60000,
      };
      passkeyService.generatePasskeyRegistrationOptions.mockResolvedValue(
        options as unknown as ReturnType<
          typeof passkeyService.generatePasskeyRegistrationOptions
        >,
      );
      await expect(controller.startPasskeyRegistration(request)).resolves.toBe(
        options,
      );
      // unbound method警告回避: 直接参照せずarrow functionで呼び出し
      const callArg = passkeyService.generatePasskeyRegistrationOptions.mock
        .calls[0][0] as string;
      expect(callArg).toBe('u');
    });
  });

  describe('finishPasskeyRegistration', () => {
    it('should call PasskeyService', async () => {
      const user: User = {
        id: 'u',
        email: 'a@b.com',
        password: '',
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      const request = createRequestMock(user);
      const dto: PasskeyRegisterFinishDto = {
        response: {},
        challenge: 'c',
      } as PasskeyRegisterFinishDto;
      const verified: TestVerifiedRegistrationResponse = {
        verified: true,
        registrationInfo: {
          credential: { id: 'id', publicKey: Buffer.from(''), counter: 0 },
          fmt: 'none',
          aaguid: 'aaguid',
        },
      };
      passkeyService.verifyPasskeyRegistration.mockResolvedValue(
        verified as unknown as ReturnType<
          typeof passkeyService.verifyPasskeyRegistration
        >,
      );
      await expect(
        controller.finishPasskeyRegistration(request, dto),
      ).resolves.toEqual(verified);
      const regCall0 = passkeyService.verifyPasskeyRegistration.mock
        .calls[0][0] as string;
      const regCall1 = passkeyService.verifyPasskeyRegistration.mock
        .calls[0][1] as object;
      const regCall2 = passkeyService.verifyPasskeyRegistration.mock
        .calls[0][2] as string;
      expect(regCall0).toBe('u');
      expect(regCall1).toEqual({});
      expect(regCall2).toBe('c');
    });
  });

  describe('startPasskeyLogin', () => {
    it('should call PasskeyService', async () => {
      const options: TestPublicKeyCredentialCreationOptionsJSON = {
        rp: { name: 'authsome', id: 'localhost' },
        user: { id: 'u', name: 'a@b.com', displayName: 'a@b.com' },
        challenge: 'challenge',
        pubKeyCredParams: [],
        timeout: 60000,
      };
      passkeyService.generatePasskeyRegistrationOptions.mockResolvedValue(
        options as unknown as ReturnType<
          typeof passkeyService.generatePasskeyRegistrationOptions
        >,
      );
      // unbound method警告回避: mock.callsで直接引数を検証
      await expect(controller.startPasskeyLogin('email')).resolves.toBe(
        options,
      );
      expect(
        passkeyService.generatePasskeyRegistrationOptions.mock.calls[0][0],
      ).toBe('email');
    });
    it('should throw if emailOrUserId is missing', async () => {
      await expect(controller.startPasskeyLogin(undefined)).rejects.toThrow();
    });
  });

  describe('finishPasskeyLogin', () => {
    it('should call PasskeyService', async () => {
      const dto: PasskeyLoginFinishDto = {
        response: {},
        challenge: 'c',
      } as PasskeyLoginFinishDto;
      const result = { accessToken: 'a', refreshToken: 'r', userId: 'u' };
      passkeyService.verifyPasskeyAuthentication.mockResolvedValue(result);
      await expect(
        controller.finishPasskeyLogin(
          { user: { id: 'u' } } as FastifyRequest,
          dto,
        ),
      ).resolves.toEqual(result);
      const authCall0 = passkeyService.verifyPasskeyAuthentication.mock
        .calls[0][0] as object;
      const authCall1 = passkeyService.verifyPasskeyAuthentication.mock
        .calls[0][1] as string;
      expect(authCall0).toEqual(dto.response);
      expect(authCall1).toBe(dto.challenge);
    });
  });

  describe('getPasskeyCredentials', () => {
    it('should call PasskeyService', async () => {
      const user: User = {
        id: 'u',
        email: 'a@b.com',
        password: '',
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      const request = createRequestMock(user);
      const cred: Pick<
        WebAuthnCredential,
        | 'id'
        | 'credentialId'
        | 'transports'
        | 'attestationType'
        | 'aaguid'
        | 'name'
        | 'createdAt'
      > = {
        id: 'id',
        credentialId: 'cid',
        transports: [],
        attestationType: 'none',
        aaguid: 'aaguid',
        name: 'n',
        createdAt: new Date(),
      };
      passkeyService.getPasskeyCredentials.mockResolvedValue([cred]);
      await expect(controller.getPasskeyCredentials(request)).resolves.toEqual([
        cred,
      ]);
      expect(passkeyService.getPasskeyCredentials.mock.calls[0][0]).toBe('u');
    });
  });

  describe('deletePasskeyCredential', () => {
    it('should call PasskeyService and return message', async () => {
      const user: User = {
        id: 'u',
        email: 'a@b.com',
        password: '',
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      const request = createRequestMock(user);
      passkeyService.deletePasskeyCredential.mockResolvedValue(undefined);
      await expect(
        controller.deletePasskeyCredential(request, 'cid'),
      ).resolves.toEqual({
        message: 'Passkey credential deleted successfully',
      });
      const delCall1 = passkeyService.deletePasskeyCredential.mock
        .calls[0][1] as string;
      expect(delCall1).toBe('cid');
    });
  });

  describe('getIdentities', () => {
    it('should call AuthService', async () => {
      const user: User = {
        id: 'u',
        email: 'a@b.com',
        password: '',
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      const request = createRequestMock(user);
      const identity = {
        id: 'id',
        provider: 'google',
        email: 'a@b.com',
        createdAt: new Date(),
      };
      authService.getIdentities.mockResolvedValue([identity]);
      await expect(controller.getIdentities(request)).resolves.toEqual([
        identity,
      ]);
      expect(authService.getIdentities.mock.calls[0][0]).toBe('u');
    });
  });

  describe('deleteIdentity', () => {
    it('should call AuthService and return message', async () => {
      const user: User = {
        id: 'u',
        email: 'a@b.com',
        password: '',
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      const request = createRequestMock(user);
      authService.deleteIdentity.mockResolvedValue(undefined);
      await expect(controller.deleteIdentity(request, 'id')).resolves.toEqual({
        message: 'Identity deleted successfully',
      });
      expect(authService.deleteIdentity.mock.calls[0][0]).toBe('u');
      expect(authService.deleteIdentity.mock.calls[0][1]).toBe('id');
    });
  });

  describe('verifyJwt', () => {
    it('should return valid true and payload if JWT is valid', async () => {
      // Arrange
      const token = 'valid.jwt.token';
      const payload = { sub: 'user1', email: 'a@b.com' };
      // @ts-expect-error: partial mock
      controller._jwtService = {
        verifyAsync: vi.fn().mockResolvedValue(payload),
      };
      // Act
      const result = await controller.verifyJwt({ token });
      // Assert
      expect(result).toEqual({ valid: true, payload });
    });
    it('should throw UnauthorizedException if JWT is invalid', async () => {
      // Arrange
      const token = 'invalid.jwt.token';
      // @ts-expect-error: partial mock
      controller._jwtService = {
        verifyAsync: vi.fn().mockRejectedValue(new Error('invalid')),
      };
      // Act & Assert
      await expect(controller.verifyJwt({ token })).rejects.toThrow(
        'Invalid JWT',
      );
    });
  });
});
