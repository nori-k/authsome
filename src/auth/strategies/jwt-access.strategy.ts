import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy as JwtStrategy, ExtractJwt } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from 'src/prisma/prisma.service';
import type { FastifyRequest } from 'fastify';

@Injectable()
export class JwtAccessStrategy extends PassportStrategy(
  JwtStrategy,
  'jwt-access',
) {
  constructor(
    private readonly _configService: ConfigService,
    private readonly _prisma: PrismaService,
  ) {
    // 型エラー・unused引数警告を避けるため、型アサーションのextractors引数名を _extractors にし、インデントも修正
    super({
      jwtFromRequest: (
        ExtractJwt.fromExtractors as unknown as (
          _extractors: Array<(_req: FastifyRequest) => string | null>,
        ) => (_req: FastifyRequest) => string | null
      )([
        (_req: FastifyRequest) => {
          const authHeader = _req.headers?.authorization;
          if (
            typeof authHeader === 'string' &&
            authHeader.startsWith('Bearer ')
          ) {
            return authHeader.split(' ')[1];
          }
          const accessToken = _req.cookies?.['access_token'];
          if (typeof accessToken === 'string' && accessToken !== '') {
            return accessToken;
          }
          return null;
        },
      ]),
      ignoreExpiration: false,
      secretOrKey: _configService.get<string>('JWT_ACCESS_SECRET'),
    });
  }

  validate(payload: { sub: string }): { userId: string } {
    if (!payload?.sub) {
      throw new UnauthorizedException('Invalid JWT payload');
    }
    return { userId: payload.sub };
  }
}
