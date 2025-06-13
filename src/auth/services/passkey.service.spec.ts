import { vi } from 'vitest';
vi.mock('@simplewebauthn/server', async () => {
  const actual = await vi.importActual('@simplewebauthn/server');
  return {
    ...actual,
    verifyAuthenticationResponse: vi.fn(),
  };
});
import * as simpleWebauthn from '@simplewebauthn/server';
import type {
  PasskeyAttestationResponse,
  PasskeyAssertionResponse,
} from '../dto/passkey.dto';
import { PasskeyService } from './passkey.service';
import { PrismaService } from '../../prisma/prisma.service';
import { type TestingModule, Test } from '@nestjs/testing';

describe('PasskeyService', () => {
  let service: PasskeyService;
  let prisma: PrismaService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        PasskeyService,
        {
          provide: PrismaService,
          useValue: {
            user: {
              findUnique: vi.fn(),
            },
            webAuthnCredential: {
              findMany: vi.fn(),
              findUnique: vi.fn(),
              create: vi.fn(),
              update: vi.fn(),
              delete: vi.fn(),
            },
          },
        },
      ],
    }).compile();
    service = module.get<PasskeyService>(PasskeyService);
    prisma = module.get<PrismaService>(PrismaService);
    // --- 依存サービスをprivateプロパティに直接注入 ---
    // @ts-expect-error: テスト用にprivate _prismaへ直接代入して依存注入
    service._prisma = prisma;
  });

  // afterEachでmockをリセット
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('generatePasskeyRegistrationOptions', () => {
    it('returns options if user and email exist', async () => {
      // @ts-expect-error: vitestの型制約回避のため、mockResolvedValueを直接利用
      prisma.user.findUnique.mockResolvedValue({
        id: 'u1',
        email: 'a@example.com',
      });
      // @ts-expect-error: vitestの型制約回避のため、mockResolvedValueを直接利用
      prisma.webAuthnCredential.findMany.mockResolvedValue([]);
      const result = await service.generatePasskeyRegistrationOptions('u1');
      expect(result).toHaveProperty('challenge');
      expect(result).toHaveProperty('user');
    });
    it('throws if user not found', async () => {
      // @ts-expect-error: vitestの型制約回避のため、mockResolvedValueを直接利用
      prisma.user.findUnique.mockResolvedValue(null);
      await expect(
        service.generatePasskeyRegistrationOptions('nouser'),
      ).rejects.toThrow('User not found or email missing');
    });
    it('throws if email missing', async () => {
      // @ts-expect-error: vitestの型制約回避のため、mockResolvedValueを直接利用
      prisma.user.findUnique.mockResolvedValue({
        id: 'u1',
        email: '',
      });
      await expect(
        service.generatePasskeyRegistrationOptions('u1'),
      ).rejects.toThrow('User not found or email missing');
    });
  });

  describe('verifyPasskeyRegistration', () => {
    it('throws if user not found', async () => {
      // @ts-expect-error: vitestの型制約回避のため、mockResolvedValueを直接利用
      prisma.user.findUnique.mockResolvedValue(null);
      await expect(
        service.verifyPasskeyRegistration(
          'nouser',
          {} as PasskeyAttestationResponse,
          'c',
        ),
      ).rejects.toThrow('User not found or email missing');
    });
    it('throws if email missing', async () => {
      // @ts-expect-error: vitestの型制約回避のため、mockResolvedValueを直接利用
      prisma.user.findUnique.mockResolvedValue({
        id: 'u1',
        email: '',
      });
      await expect(
        service.verifyPasskeyRegistration(
          'u1',
          {} as PasskeyAttestationResponse,
          'c',
        ),
      ).rejects.toThrow('User not found or email missing');
    });
    it('throws if attestation response is invalid', async () => {
      // @ts-expect-error: vitestの型制約回避のため、mockResolvedValueを直接利用
      prisma.user.findUnique.mockResolvedValue({
        id: 'u1',
        email: 'a@example.com',
      });
      // _verifyAttestationResponseをモックして失敗させる
      vi.spyOn(
        service as unknown as { _verifyAttestationResponse: () => void },
        '_verifyAttestationResponse',
      ).mockImplementation(() => {
        throw new Error('Attestation invalid');
      });
      await expect(
        service.verifyPasskeyRegistration(
          'u1',
          {} as PasskeyAttestationResponse,
          'c',
        ),
      ).rejects.toThrow('Attestation invalid');
    });
  });

  describe('verifyPasskeyAuthentication', () => {
    it('throws if credential not found', async () => {
      // @ts-expect-error: vitestの型制約回避のため、mockResolvedValueを直接利用
      prisma.webAuthnCredential.findUnique.mockResolvedValue(null);
      await expect(
        service.verifyPasskeyAuthentication(
          { id: 'cid' } as PasskeyAssertionResponse,
          'c',
        ),
      ).rejects.toThrow('Credential not found');
    });
    it('throws if user not found', async () => {
      // @ts-expect-error: vitestの型制約回避のため、mockResolvedValueを直接利用
      prisma.webAuthnCredential.findUnique.mockResolvedValue({
        credentialId: 'cid',
        userId: 'u1',
        transports: [],
        publicKey: '',
        counter: 0,
      });
      // @ts-expect-error: vitestの型制約回避のため、mockResolvedValueを直接利用
      prisma.user.findUnique.mockResolvedValue(null);
      await expect(
        service.verifyPasskeyAuthentication(
          { id: 'cid', response: {} } as PasskeyAssertionResponse,
          'c',
        ),
      ).rejects.toThrow('User not found');
    });
    it('throws if authentication response is invalid', async () => {
      // @ts-expect-error: vitestの型制約回避のため、mockResolvedValueを直接利用
      prisma.webAuthnCredential.findUnique.mockResolvedValue({
        credentialId: 'cid',
        userId: 'u1',
        transports: [],
        publicKey: '',
        counter: 0,
      });
      // @ts-expect-error: vitestの型制約回避のため、mockResolvedValueを直接利用
      prisma.user.findUnique.mockResolvedValue({
        id: 'u1',
        email: 'a@example.com',
      });
      const dummyAssertion: PasskeyAssertionResponse = {
        id: 'cid',
        rawId: [1, 2, 3],
        response: {
          authenticatorData: [1, 2, 3],
          clientDataJSON: [1, 2, 3],
          signature: [1, 2, 3],
        },
        type: 'public-key',
        clientExtensionResults: {},
      };
      (
        simpleWebauthn.verifyAuthenticationResponse as unknown as {
          mockImplementation: (..._args: unknown[]) => unknown;
        }
      ).mockImplementation(() => ({ verified: false }));
      await expect(
        service.verifyPasskeyAuthentication(dummyAssertion, 'c'),
      ).rejects.toThrow('Passkey authentication failed');
      vi.restoreAllMocks();
    });
  });

  describe('getWebAuthnCredentialById', () => {
    it('returns credential if found', async () => {
      prisma.webAuthnCredential.findUnique = vi.fn().mockResolvedValue({
        id: 'cid',
      });
      const result = await service.getWebAuthnCredentialById('cid');
      expect(result).toEqual({ id: 'cid' });
    });
    it('returns null if not found', async () => {
      prisma.webAuthnCredential.findUnique = vi.fn().mockResolvedValue(null);
      const result = await service.getWebAuthnCredentialById('cid');
      expect(result).toBeNull();
    });
  });

  describe('deleteWebAuthnCredentialById', () => {
    it('calls delete', async () => {
      prisma.webAuthnCredential.delete = vi.fn().mockResolvedValue({});
      await expect(
        service.deleteWebAuthnCredentialById('cid'),
      ).resolves.toBeUndefined();
    });
  });

  describe('getPasskeyCredentials', () => {
    it('returns credentials', async () => {
      prisma.webAuthnCredential.findMany = vi
        .fn()
        .mockResolvedValue([{ id: 'cid' }]);
      const result = await service.getPasskeyCredentials('u1');
      expect(result).toEqual([{ id: 'cid' }]);
    });
    it('returns empty array if user has no credentials', async () => {
      prisma.webAuthnCredential.findMany = vi.fn().mockResolvedValue([]);
      const result = await service.getPasskeyCredentials('nouser');
      expect(result).toEqual([]);
    });
  });

  describe('deletePasskeyCredential', () => {
    it('calls delete if credential belongs to user', async () => {
      prisma.webAuthnCredential.findUnique = vi.fn().mockResolvedValue({
        id: 'cid',
        userId: 'u1',
      });
      prisma.webAuthnCredential.delete = vi.fn().mockResolvedValue({});
      await expect(
        service.deletePasskeyCredential('u1', 'cid'),
      ).resolves.toBeUndefined();
      // deleteメソッドの呼び出し履歴を直接検証
      const calls = (
        prisma.webAuthnCredential.delete as unknown as {
          mock: { calls: unknown[][] };
        }
      ).mock.calls;
      expect(calls[0][0]).toEqual({ where: { id: 'cid' } });
    });
    it('throws UnauthorizedException if credential does not belong to user', async () => {
      prisma.webAuthnCredential.findUnique = vi.fn().mockResolvedValue({
        id: 'cid',
        userId: 'otherUser',
      });
      await expect(
        service.deletePasskeyCredential('u1', 'cid'),
      ).rejects.toThrow('Credential not found or not owned by user');
    });
    it('throws UnauthorizedException if credential not found', async () => {
      prisma.webAuthnCredential.findUnique = vi.fn().mockResolvedValue(null);
      await expect(
        service.deletePasskeyCredential('u1', 'cid'),
      ).rejects.toThrow('Credential not found or not owned by user');
    });
  });

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  interface Validator {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/no-unused-vars
    _validateAttestationFields: (_r: unknown) => void;
  }

  describe('private _validateAttestationFields', () => {
    function makeBase(): PasskeyAttestationResponse {
      return {
        id: 'id',
        rawId: [1],
        response: { attestationObject: [1], clientDataJSON: [1] },
        type: 'public-key',
        clientExtensionResults: {},
      };
    }
    function getValidator(): Validator {
      return service as unknown as Validator;
    }
    it('throws if rawId is missing', () => {
      const s = getValidator();
      const input = makeBase();
      (input as Partial<PasskeyAttestationResponse>).rawId = undefined;
      expect(() => s._validateAttestationFields(input)).toThrowError(
        'Attestation invalid',
      );
    });
    it('throws if attestationObject is missing', () => {
      const s = getValidator();
      const input = makeBase();
      // eslint-disable-next-line @typescript-eslint/ban-ts-comment
      // @ts-expect-error: 故意に型不正
      input.response.attestationObject = undefined;
      expect(() => s._validateAttestationFields(input)).toThrowError(
        'Attestation invalid',
      );
    });
    it('throws if clientDataJSON is missing', () => {
      const s = getValidator();
      const input = makeBase();
      // eslint-disable-next-line @typescript-eslint/ban-ts-comment
      // @ts-expect-error: 故意に型不正
      input.response.clientDataJSON = undefined;
      expect(() => s._validateAttestationFields(input)).toThrowError(
        'Attestation invalid',
      );
    });
    it('does not throw if all fields exist', () => {
      const s = getValidator();
      expect(() => s._validateAttestationFields(makeBase())).not.toThrow();
    });
  });
});
