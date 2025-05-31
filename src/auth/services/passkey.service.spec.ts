import { Test, type TestingModule } from '@nestjs/testing';
import { PasskeyService } from './passkey.service';
import { PrismaService } from '../../prisma/prisma.service';
import type {
  PasskeyAttestationResponse,
  PasskeyAssertionResponse,
} from '../dto/passkey.dto';
jest.mock('@simplewebauthn/server', () => {
  const actual: Record<string, unknown> = jest.requireActual(
    '@simplewebauthn/server',
  );
  return {
    ...actual,
    verifyAuthenticationResponse: jest.fn(),
  } as typeof actual;
});
import * as simpleWebauthn from '@simplewebauthn/server';

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
              findUnique: jest.fn(),
            },
            webAuthnCredential: {
              findMany: jest.fn(),
              findUnique: jest.fn(),
              create: jest.fn(),
              update: jest.fn(),
              delete: jest.fn(),
            },
          },
        },
      ],
    }).compile();
    service = module.get<PasskeyService>(PasskeyService);
    prisma = module.get<PrismaService>(PrismaService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('generatePasskeyRegistrationOptions', () => {
    it('returns options if user and email exist', async () => {
      (prisma.user.findUnique as jest.Mock).mockResolvedValue({
        id: 'u1',
        email: 'a@example.com',
      });
      (prisma.webAuthnCredential.findMany as jest.Mock).mockResolvedValue([]);
      const result = await service.generatePasskeyRegistrationOptions('u1');
      expect(result).toHaveProperty('challenge');
      expect(result).toHaveProperty('user');
    });
    it('throws if user not found', async () => {
      (prisma.user.findUnique as jest.Mock).mockResolvedValue(null);
      await expect(
        service.generatePasskeyRegistrationOptions('nouser'),
      ).rejects.toThrow('User not found or email missing');
    });
    it('throws if email missing', async () => {
      (prisma.user.findUnique as jest.Mock).mockResolvedValue({
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
      (prisma.user.findUnique as jest.Mock).mockResolvedValue(null);
      await expect(
        service.verifyPasskeyRegistration(
          'nouser',
          {} as PasskeyAttestationResponse,
          'c',
        ),
      ).rejects.toThrow('User not found or email missing');
    });
    it('throws if email missing', async () => {
      (prisma.user.findUnique as jest.Mock).mockResolvedValue({
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
      (prisma.user.findUnique as jest.Mock).mockResolvedValue({
        id: 'u1',
        email: 'a@example.com',
      });
      // _verifyAttestationResponseをモックして失敗させる
      jest
        .spyOn(
          service as unknown as { _verifyAttestationResponse: () => void },
          '_verifyAttestationResponse',
        )
        .mockImplementation(() => {
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
      (prisma.webAuthnCredential.findUnique as jest.Mock).mockResolvedValue(
        null,
      );
      await expect(
        service.verifyPasskeyAuthentication(
          { id: 'cid' } as PasskeyAssertionResponse,
          'c',
        ),
      ).rejects.toThrow('Credential not found');
    });
    it('throws if user not found', async () => {
      (prisma.webAuthnCredential.findUnique as jest.Mock).mockResolvedValue({
        credentialId: 'cid',
        userId: 'u1',
        transports: [],
        publicKey: '',
        counter: 0,
      });
      (prisma.user.findUnique as jest.Mock).mockResolvedValue(null);
      await expect(
        service.verifyPasskeyAuthentication(
          { id: 'cid', response: {} } as PasskeyAssertionResponse,
          'c',
        ),
      ).rejects.toThrow('User not found');
    });
    it('throws if authentication response is invalid', async () => {
      (prisma.webAuthnCredential.findUnique as jest.Mock).mockResolvedValue({
        credentialId: 'cid',
        userId: 'u1',
        transports: [],
        publicKey: '',
        counter: 0,
      });
      (prisma.user.findUnique as jest.Mock).mockResolvedValue({
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
        simpleWebauthn.verifyAuthenticationResponse as jest.Mock
      ).mockImplementation(() => ({ verified: false }));
      await expect(
        service.verifyPasskeyAuthentication(dummyAssertion, 'c'),
      ).rejects.toThrow('Passkey authentication failed');
      jest.resetAllMocks();
    });
  });

  describe('getWebAuthnCredentialById', () => {
    it('returns credential if found', async () => {
      (prisma.webAuthnCredential.findUnique as jest.Mock).mockResolvedValue({
        id: 'cid',
      });
      const result = await service.getWebAuthnCredentialById('cid');
      expect(result).toEqual({ id: 'cid' });
    });
    it('returns null if not found', async () => {
      (prisma.webAuthnCredential.findUnique as jest.Mock).mockResolvedValue(
        null,
      );
      const result = await service.getWebAuthnCredentialById('cid');
      expect(result).toBeNull();
    });
  });

  describe('deleteWebAuthnCredentialById', () => {
    it('calls delete', async () => {
      (prisma.webAuthnCredential.delete as jest.Mock).mockResolvedValue({});
      await expect(
        service.deleteWebAuthnCredentialById('cid'),
      ).resolves.toBeUndefined();
    });
  });

  describe('getPasskeyCredentials', () => {
    it('returns credentials', async () => {
      (prisma.webAuthnCredential.findMany as jest.Mock).mockResolvedValue([
        { id: 'cid' },
      ]);
      const result = await service.getPasskeyCredentials('u1');
      expect(result).toEqual([{ id: 'cid' }]);
    });
    it('returns empty array if user has no credentials', async () => {
      (prisma.webAuthnCredential.findMany as jest.Mock).mockResolvedValue([]);
      const result = await service.getPasskeyCredentials('nouser');
      expect(result).toEqual([]);
    });
  });

  describe('deletePasskeyCredential', () => {
    it('calls delete if credential belongs to user', async () => {
      // Mock credential lookup to return a credential with matching userId
      (prisma.webAuthnCredential.findUnique as jest.Mock).mockResolvedValue({
        id: 'cid',
        userId: 'u1',
      });
      (prisma.webAuthnCredential.delete as jest.Mock).mockResolvedValue({});
      await expect(
        service.deletePasskeyCredential('u1', 'cid'),
      ).resolves.toBeUndefined();
      // Assert the delete mock was called with the correct argument using mock.calls safely
      const deleteMock = jest.spyOn(prisma.webAuthnCredential, 'delete');
      expect(deleteMock).toHaveBeenCalledWith({ where: { id: 'cid' } });
    });
    it('throws UnauthorizedException if credential does not belong to user', async () => {
      // Mock credential lookup to return a credential with a different userId
      (prisma.webAuthnCredential.findUnique as jest.Mock).mockResolvedValue({
        id: 'cid',
        userId: 'otherUser',
      });
      await expect(
        service.deletePasskeyCredential('u1', 'cid'),
      ).rejects.toThrow('Credential not found or not owned by user');
    });
    it('throws UnauthorizedException if credential not found', async () => {
      (prisma.webAuthnCredential.findUnique as jest.Mock).mockResolvedValue(
        null,
      );
      await expect(
        service.deletePasskeyCredential('u1', 'cid'),
      ).rejects.toThrow('Credential not found or not owned by user');
    });
  });
});
