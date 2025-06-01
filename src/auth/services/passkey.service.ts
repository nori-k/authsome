import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';
import {
  AuthenticatorTransportFuture,
  generateRegistrationOptions,
  verifyRegistrationResponse,
  verifyAuthenticationResponse,
  VerifiedRegistrationResponse,
  AuthenticationResponseJSON,
} from '@simplewebauthn/server';
import {
  PasskeyAttestationResponse,
  PasskeyAttestationResponseInner,
  PasskeyAssertionResponse,
} from '../dto/passkey.dto';
import type { WebAuthnCredential } from '@prisma/client';

@Injectable()
export class PasskeyService {
  constructor(private readonly _prisma: PrismaService) {}

  /**
   * Generate FIDO2/WebAuthn registration options for a user.
   * @param userId User id
   * @returns Registration options
   */
  async generatePasskeyRegistrationOptions(
    userIdOrEmail: string,
  ): Promise<ReturnType<typeof generateRegistrationOptions>> {
    // ユーザーIDで検索し、なければメールアドレスで検索
    let user = await this._prisma.user.findUnique({
      where: { id: userIdOrEmail },
    });
    user ??= await this._prisma.user.findUnique({
      where: { email: userIdOrEmail },
    });
    if (!user?.email) {
      throw new UnauthorizedException('User not found or email missing');
    }
    const credentials = await this._prisma.webAuthnCredential.findMany({
      where: { userId: user.id },
    });
    const options = generateRegistrationOptions({
      rpName: 'authsome',
      rpID: process.env.RP_ID ?? 'localhost',
      userID: Buffer.from(user.id),
      userName: user.email,
      userDisplayName: user.email,
      attestationType: 'none',
      excludeCredentials: credentials.map((c) => ({
        id: c.credentialId,
        transports: (c.transports ?? []).filter(
          (t): t is AuthenticatorTransportFuture =>
            [
              'usb',
              'ble',
              'nfc',
              'internal',
              'cable',
              'hybrid',
              'smart-card',
            ].includes(t as AuthenticatorTransportFuture),
        ),
      })),
      authenticatorSelection: { userVerification: 'preferred' },
    });
    return options;
  }

  private async _getAndValidateUser(
    userId: string,
  ): Promise<{ id: string; email: string | null }> {
    const user = await this._prisma.user.findUnique({ where: { id: userId } });
    if (!user?.email) {
      throw new UnauthorizedException('User not found or email missing');
    }
    return user;
  }

  private _validateAttestationFields(
    response: PasskeyAttestationResponse,
  ): void {
    if (
      !response.rawId ||
      !response.response?.attestationObject ||
      !response.response?.clientDataJSON
    ) {
      throw new Error('Attestation invalid');
    }
  }

  private _bufferizeAttestationResponse(
    response: PasskeyAttestationResponse,
  ): Omit<PasskeyAttestationResponse, 'rawId' | 'response'> & {
    rawId: Buffer;
    response: Omit<
      PasskeyAttestationResponseInner,
      'attestationObject' | 'clientDataJSON'
    > & {
      attestationObject: Buffer;
      clientDataJSON: Buffer;
    };
  } {
    return {
      ...response,
      rawId: Buffer.from(response.rawId),
      response: {
        ...response.response,
        attestationObject: Buffer.from(response.response.attestationObject),
        clientDataJSON: Buffer.from(response.response.clientDataJSON),
      },
    };
  }

  /**
   * Verify FIDO2/WebAuthn registration response and store credential.
   * @param userId User id
   * @param response Attestation response
   * @param challenge Challenge string
   * @returns Verification result
   */
  async verifyPasskeyRegistration(
    userId: string,
    response: PasskeyAttestationResponse,
    challenge: string,
  ): Promise<VerifiedRegistrationResponse | null> {
    const user = await this._getAndValidateUser(userId);
    this._validateAttestationFields(response);
    const bufferized = this._bufferizeAttestationResponse(response);
    const verification = await this._verifyAttestationResponse(
      bufferized as unknown,
      challenge,
    );
    if (!verification.verified || !verification.registrationInfo) {
      throw new UnauthorizedException('Passkey registration failed');
    }
    const info = verification.registrationInfo;
    const cred = info.credential;
    await this._prisma.webAuthnCredential.create({
      data: {
        userId: user.id,
        credentialId: cred.id,
        publicKey: Buffer.from(cred.publicKey).toString('base64url'),
        counter: BigInt(cred.counter),
        transports: response.response.transports ?? [],
        attestationType: info.fmt,
        aaguid: info.aaguid,
        name: user.email,
      },
    });
    return verification;
  }

  // _verifyAttestationResponseの引数型をunknownに
  private async _verifyAttestationResponse(
    response: unknown,
    challenge: string,
  ): Promise<VerifiedRegistrationResponse> {
    const r = response as {
      id: string;
      rawId: Buffer;
      response: {
        attestationObject: Buffer;
        clientDataJSON: Buffer;
        transports?: string[];
      };
      type: string;
      clientExtensionResults: Record<string, unknown>;
    };
    return verifyRegistrationResponse({
      response: {
        id: r.id,
        rawId: r.rawId.toString('base64url'),
        response: {
          attestationObject: r.response.attestationObject.toString('base64url'),
          clientDataJSON: r.response.clientDataJSON.toString('base64url'),
          transports: (r.response.transports ?? []).filter(
            (t): t is AuthenticatorTransportFuture =>
              [
                'usb',
                'ble',
                'nfc',
                'internal',
                'cable',
                'hybrid',
                'smart-card',
              ].includes(t as AuthenticatorTransportFuture),
          ),
        },
        clientExtensionResults:
          typeof r.clientExtensionResults === 'object' &&
          r.clientExtensionResults !== null
            ? (r.clientExtensionResults as AuthenticationExtensionsClientOutputs)
            : {},
        type: 'public-key',
      },
      expectedChallenge: challenge,
      expectedOrigin: process.env.WEBAUTHN_ORIGIN ?? 'http://localhost:8080',
      expectedRPID: process.env.RP_ID ?? 'localhost',
    });
  }

  /**
   * Verify FIDO2/WebAuthn authentication response and return tokens.
   * @param response Assertion response
   * @param challenge Challenge string
   * @returns Tokens and userId
   */
  async verifyPasskeyAuthentication(
    response: PasskeyAssertionResponse,
    challenge: string,
  ): Promise<{ accessToken: string; refreshToken: string; userId: string }> {
    // 1. credential特定
    const credId = response.id;
    const credential = await this._prisma.webAuthnCredential.findUnique({
      where: { credentialId: credId },
    });
    if (!credential) throw new UnauthorizedException('Credential not found');
    const user = await this._prisma.user.findUnique({
      where: { id: credential.userId },
    });
    if (!user) throw new UnauthorizedException('User not found');
    // 2. 検証
    const allowedTransports = [
      'usb',
      'ble',
      'nfc',
      'internal',
      'cable',
      'hybrid',
      'smart-card',
    ] as AuthenticatorTransportFuture[];
    const transports = (credential.transports ?? []).filter(
      (t: string): t is AuthenticatorTransportFuture =>
        allowedTransports.includes(t as AuthenticatorTransportFuture),
    );
    const webauthnCredential = {
      id: credential.credentialId,
      publicKey: Buffer.from(credential.publicKey, 'base64url'),
      counter: Number(credential.counter),
      transports,
    };
    function passkeyAssertionDtoToJson(
      dto: PasskeyAssertionResponse,
    ): AuthenticationResponseJSON {
      return {
        id: dto.id,
        rawId: Buffer.from(dto.rawId).toString('base64url'),
        response: {
          authenticatorData: Buffer.from(
            dto.response.authenticatorData,
          ).toString('base64url'),
          clientDataJSON: Buffer.from(dto.response.clientDataJSON).toString(
            'base64url',
          ),
          signature: Buffer.from(dto.response.signature).toString('base64url'),
          userHandle: dto.response.userHandle
            ? Buffer.from(dto.response.userHandle).toString('base64url')
            : undefined,
        },
        type: 'public-key',
        clientExtensionResults: {},
      };
    }
    const verification = await verifyAuthenticationResponse({
      response: passkeyAssertionDtoToJson(response),
      expectedChallenge: challenge,
      expectedOrigin: process.env.WEBAUTHN_ORIGIN ?? 'http://localhost:3000',
      expectedRPID: process.env.RP_ID ?? 'localhost',
      credential: webauthnCredential,
      requireUserVerification: true,
    });
    if (!verification.verified)
      throw new UnauthorizedException('Passkey authentication failed');
    // 3. カウンタ更新
    if (
      typeof verification.authenticationInfo === 'object' &&
      verification.authenticationInfo !== null
    ) {
      await this._prisma.webAuthnCredential.update({
        where: { credentialId: credId },
        data: { counter: BigInt(verification.authenticationInfo.newCounter) },
      });
    }
    // 4. JWT発行はAuthServiceで行うべき。ここではuserIdのみ返す。
    return { accessToken: '', refreshToken: '', userId: user.id };
  }

  /**
   * Get a WebAuthn credential by id.
   * @param id Credential id
   * @returns WebAuthnCredential or null
   */
  async getWebAuthnCredentialById(
    id: string,
  ): Promise<WebAuthnCredential | null> {
    return this._prisma.webAuthnCredential.findUnique({ where: { id } });
  }

  /**
   * Delete a WebAuthn credential by id.
   * @param id Credential id
   */
  async deleteWebAuthnCredentialById(id: string): Promise<void> {
    await this._prisma.webAuthnCredential.delete({ where: { id } });
  }

  /**
   * List all passkey credentials for a user.
   * @param userId User id
   * @returns Array of credential info
   */
  async getPasskeyCredentials(
    userId: string,
  ): Promise<
    Pick<
      WebAuthnCredential,
      | 'id'
      | 'credentialId'
      | 'transports'
      | 'attestationType'
      | 'aaguid'
      | 'name'
      | 'createdAt'
    >[]
  > {
    return this._prisma.webAuthnCredential.findMany({
      where: { userId },
      select: {
        id: true,
        credentialId: true,
        transports: true,
        attestationType: true,
        aaguid: true,
        name: true,
        createdAt: true,
      },
    });
  }

  async deletePasskeyCredential(
    userId: string,
    credentialId: string,
  ): Promise<void> {
    const credential = await this._prisma.webAuthnCredential.findUnique({
      where: { id: credentialId },
    });
    if (!credential || credential.userId !== userId) {
      throw new UnauthorizedException(
        'Credential not found or not owned by user',
      );
    }
    await this._prisma.webAuthnCredential.delete({
      where: { id: credentialId },
    });
  }
}
