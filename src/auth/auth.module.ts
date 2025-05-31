import { Module } from '@nestjs/common';
import { AuthService } from './services/auth.service';
import { AuthController } from './auth.controller';
import { PrismaModule } from 'src/prisma/prisma.module';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { ConfigModule } from '@nestjs/config';
import { JwtAccessStrategy } from './strategies/jwt-access.strategy';
import { JwtRefreshStrategy } from './strategies/jwt-refresh.strategy';
import { GoogleStrategy } from './strategies/google.strategy';
import { AppleStrategy } from './strategies/apple.strategy';
import { PasskeyService } from './services/passkey.service';

@Module({
  imports: [
    PrismaModule,
    PassportModule,
    JwtModule.register({}),
    ConfigModule, // ConfigModuleをインポート
  ],
  providers: [
    AuthService,
    PasskeyService,
    JwtAccessStrategy,
    JwtRefreshStrategy,
    GoogleStrategy,
    AppleStrategy,
  ],
  controllers: [AuthController],
  exports: [AuthService],
})
export class AuthModule {}
