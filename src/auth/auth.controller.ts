import {
  Controller,
  Post,
  Req,
  UseGuards,
  Body as NestBody,
  Get,
  Res,
  Delete,
  Param,
} from '@nestjs/common';
import { AuthService } from './services/auth.service';
import {
  AuthRegisterDto,
  AuthLoginDto,
  PasskeyRegisterFinishDto,
  PasskeyLoginFinishDto,
} from './dto/auth.dto';
import { AuthGuard } from '@nestjs/passport';
import { FastifyRequest, FastifyReply } from 'fastify';
import { User } from '@prisma/client';
import { PasskeyService } from './services/passkey.service';
import type { VerifiedRegistrationResponse } from '@simplewebauthn/server';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly _authService: AuthService,
    private readonly _passkeyService: PasskeyService,
  ) {}

  /**
   * Set JWT tokens as cookies in the response.
   * @param reply FastifyReply
   * @param accessToken JWT access token
   * @param refreshToken JWT refresh token
   */
  private setAuthCookies(
    reply: FastifyReply,
    accessToken: string,
    refreshToken: string,
  ): void {
    // Fastify expects seconds for maxAge
    reply.setCookie('access_token', accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 60 * 15, // 15 minutes
      path: '/',
    });
    reply.setCookie('refresh_token', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 60 * 60 * 24 * 7, // 7 days
      path: '/',
    });
  }

  /**
   * Register a new user with email/password.
   * @param dto Registration DTO
   * @returns User id and email
   */
  @Post('register/email-password')
  async registerEmailPassword(
    @NestBody() dto: AuthRegisterDto,
  ): Promise<{ id: string; email: string | null }> {
    return this._authService.registerEmailPassword(dto);
  }

  /**
   * Login with email/password and set tokens as cookies.
   * @param dto Login DTO
   * @param reply FastifyReply
   * @returns Tokens and userId
   */
  @Post('login/email-password')
  async loginEmailPassword(
    @NestBody() dto: AuthLoginDto,
    @Res({ passthrough: true }) reply: FastifyReply,
  ): Promise<{ accessToken: string; refreshToken: string; userId: string }> {
    const result = await this._authService.loginEmailPassword(dto);
    this.setAuthCookies(reply, result.accessToken, result.refreshToken);
    return result;
  }

  /**
   * Start Google OAuth authentication.
   */
  @Get('google')
  @UseGuards(AuthGuard('google'))
  googleAuth(): void {}

  /**
   * Google OAuth callback, set tokens as cookies and redirect.
   */
  @Get('google/callback')
  @UseGuards(AuthGuard('google'))
  googleAuthCallback(
    @Req() request: FastifyRequest,
    @Res({ passthrough: true }) reply: FastifyReply,
  ): void {
    const user = request.user as User;
    const { accessToken, refreshToken } = this._authService.generateTokens(
      user.id,
    );
    this.setAuthCookies(reply, accessToken, refreshToken);
    reply.redirect(
      `${process.env.FRONTEND_URL}/login-success?userId=${user.id}`,
    );
  }

  /**
   * Start Apple OAuth authentication.
   */
  @Get('apple')
  @UseGuards(AuthGuard('apple'))
  appleAuth(): void {}

  /**
   * Apple OAuth callback, set tokens as cookies and redirect.
   */
  @Post('apple/callback')
  @UseGuards(AuthGuard('apple'))
  appleAuthCallback(
    @Req() request: FastifyRequest,
    @Res({ passthrough: true }) reply: FastifyReply,
  ): void {
    const user = request.user as User;
    const { accessToken, refreshToken } = this._authService.generateTokens(
      user.id,
    );
    this.setAuthCookies(reply, accessToken, refreshToken);
    reply.redirect(
      `${process.env.FRONTEND_URL}/login-success?userId=${user.id}`,
    );
  }

  async refreshTokens(
    @Req() request: FastifyRequest,
    @Res({ passthrough: true }) reply: FastifyReply,
  ): Promise<{
    message: string;
    userId: string;
    accessToken: string;
    refreshToken: string;
  }> {
    const user = request.user as User;
    const oldRefreshToken = request.cookies['refresh_token'];
    const { accessToken, refreshToken, userId } =
      await this._authService.refreshTokens(user.id, oldRefreshToken);
    this.setAuthCookies(reply, accessToken, refreshToken);
    return {
      message: 'Tokens refreshed successfully!',
      userId,
      accessToken,
      refreshToken,
    };
  }

  // --- ログアウト ---
  @Post('logout')
  @UseGuards(AuthGuard('jwt-access'))
  async logout(
    @Req() request: FastifyRequest,
    @Res({ passthrough: true }) reply: FastifyReply,
  ): Promise<{ message: string }> {
    const user = request.user as User;
    const refreshToken = request.cookies['refresh_token'];
    await this._authService.logout(user.id, refreshToken);
    reply.clearCookie('access_token');
    reply.clearCookie('refresh_token');
    return { message: 'Logged out successfully!' };
  }

  // --- プロファイル取得 ---
  @UseGuards(AuthGuard('jwt-access'))
  @Get('profile')
  getProfile(@Req() request: FastifyRequest): Promise<User | undefined> {
    return Promise.resolve(request.user);
  }

  // --- Passkey (FIDO2) 関連 ---
  @UseGuards(AuthGuard('jwt-access'))
  @Post('passkey/register/start')
  async startPasskeyRegistration(
    @Req() request: FastifyRequest,
  ): Promise<PublicKeyCredentialCreationOptionsJSON> {
    const user = request.user as User;
    return this._passkeyService.generatePasskeyRegistrationOptions(user.id);
  }

  @UseGuards(AuthGuard('jwt-access'))
  @Post('passkey/register/finish')
  finishPasskeyRegistration(
    @Req() request: FastifyRequest,
    @NestBody() dto: PasskeyRegisterFinishDto,
  ): Promise<VerifiedRegistrationResponse | null> {
    const user = request.user as User;
    return this._passkeyService.verifyPasskeyRegistration(
      user.id,
      dto.response,
      dto.challenge,
    );
  }

  @Post('passkey/login/start')
  async startPasskeyLogin(
    @NestBody('emailOrUserId') emailOrUserId?: string,
  ): Promise<ReturnType<PasskeyService['generatePasskeyRegistrationOptions']>> {
    if (!emailOrUserId) throw new Error('emailOrUserId is required');
    return this._passkeyService.generatePasskeyRegistrationOptions(
      emailOrUserId,
    );
  }

  @Post('passkey/login/finish')
  async finishPasskeyLogin(
    @Req() request: FastifyRequest,
    @NestBody() dto: PasskeyLoginFinishDto,
  ): Promise<{ accessToken: string; refreshToken: string; userId: string }> {
    return this._passkeyService.verifyPasskeyAuthentication(
      dto.response,
      dto.challenge,
    );
  }

  @UseGuards(AuthGuard('jwt-access'))
  @Get('passkey/credentials')
  async getPasskeyCredentials(
    @Req() request: FastifyRequest,
  ): Promise<ReturnType<PasskeyService['getPasskeyCredentials']>> {
    const user = request.user as User;
    return this._passkeyService.getPasskeyCredentials(user.id);
  }

  @UseGuards(AuthGuard('jwt-access'))
  @Delete('passkey/credentials/:id')
  async deletePasskeyCredential(
    @Req() request: FastifyRequest,
    @Param('id') id: string,
  ): Promise<{ message: string }> {
    const user = request.user as User;
    await this._passkeyService.deletePasskeyCredential(user.id, id);
    return { message: 'Passkey credential deleted successfully' };
  }

  // --- Identity管理エンドポイント ---
  @UseGuards(AuthGuard('jwt-access'))
  @Get('identities')
  async getIdentities(
    @Req() request: FastifyRequest,
  ): Promise<ReturnType<AuthService['getIdentities']>> {
    const user = request.user as User;
    return this._authService.getIdentities(user.id);
  }

  @UseGuards(AuthGuard('jwt-access'))
  @Delete('identities/:id')
  async deleteIdentity(
    @Req() request: FastifyRequest,
    @Param('id') id: string,
  ): Promise<{ message: string }> {
    const user = request.user as User;
    await this._authService.deleteIdentity(user.id, id);
    return { message: 'Identity deleted successfully' };
  }

  @Get('identities/link/google')
  @UseGuards(AuthGuard('google'))
  linkGoogleIdentity(): void {}

  @Get('identities/link/google/callback')
  @UseGuards(AuthGuard('google'))
  linkGoogleIdentityCallback(
    @Req() request: FastifyRequest,
    @Res({ passthrough: true }) reply: FastifyReply,
  ): void {
    reply.redirect(
      `${process.env.FRONTEND_URL}/profile?message=Google account linked successfully!`,
    );
  }

  @Get('identities/link/apple')
  @UseGuards(AuthGuard('apple'))
  linkAppleIdentity(): void {}

  @Post('identities/link/apple/callback')
  @UseGuards(AuthGuard('apple'))
  linkAppleIdentityCallback(
    @Req() request: FastifyRequest,
    @Res({ passthrough: true }) reply: FastifyReply,
  ): void {
    reply.redirect(
      `${process.env.FRONTEND_URL}/profile?message=Apple account linked successfully!`,
    );
  }
}
