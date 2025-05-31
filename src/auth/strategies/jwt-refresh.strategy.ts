import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy as JwtStrategy, ExtractJwt } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from 'src/prisma/prisma.service';
import * as bcrypt from 'bcryptjs';
import type { User } from '@prisma/client';
import type { FastifyRequest } from 'fastify';

@Injectable()
export class JwtRefreshStrategy extends PassportStrategy(
  JwtStrategy,
  'jwt-refresh',
) {
  constructor(
    private readonly _prisma: PrismaService,
    private readonly configService: ConfigService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromExtractors([
        (req: FastifyRequest) => {
          const token = req?.cookies?.['refresh_token'];
          if (typeof token === 'string' && token !== '') {
            return token;
          }
          return null;
        },
      ]),
      ignoreExpiration: true,
      secretOrKey: configService.get<string>('JWT_REFRESH_SECRET'),
    });
  }

  async validate(
    payload: { sub: string },
    req: FastifyRequest,
  ): Promise<{ user: User; refreshToken: string }> {
    const user = await this._prisma.user.findUnique({
      where: { id: payload.sub },
    });
    if (!user) {
      throw new UnauthorizedException(
        'Refresh token invalid or user not found',
      );
    }

    const rawRefreshToken = req?.cookies?.['refresh_token'];
    if (typeof rawRefreshToken !== 'string' || rawRefreshToken === '') {
      throw new UnauthorizedException('Refresh token not provided in cookie');
    }
    const storedTokens = await this._prisma.refreshToken.findMany({
      where: { userId: user.id },
    });

    const validToken = storedTokens.find(
      (token) =>
        typeof token.token === 'string' &&
        bcrypt.compareSync(rawRefreshToken, token.token),
    );

    if (
      !validToken ||
      !(validToken.expiresAt instanceof Date) ||
      validToken.expiresAt < new Date()
    ) {
      throw new UnauthorizedException('Refresh token invalid or expired');
    }

    return { user, refreshToken: rawRefreshToken };
  }
}
