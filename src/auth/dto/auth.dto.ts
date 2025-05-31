// src/auth/dto/auth.dto.ts
import {
  IsEmail,
  IsString,
  IsNotEmpty,
  ValidateNested,
  MinLength,
  MaxLength,
  Matches,
} from 'class-validator';
import { Type } from 'class-transformer';
import {
  PasskeyAttestationResponse,
  PasskeyAssertionResponse,
} from './passkey.dto';

export class AuthRegisterDto {
  @IsEmail()
  @MaxLength(255)
  email: string;

  @IsString()
  @IsNotEmpty()
  @MinLength(8)
  @MaxLength(128)
  @Matches(/^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d!@#$%^&*()_+\-=]{8,128}$/, {
    message: 'Password must contain at least one letter and one number',
  })
  password: string;
}

export class AuthLoginDto {
  @IsEmail()
  @MaxLength(255)
  email: string;

  @IsString()
  @IsNotEmpty()
  @MinLength(8)
  @MaxLength(128)
  password: string;
}

export class PasskeyRegisterFinishDto {
  @ValidateNested()
  @Type(() => Object)
  response: PasskeyAttestationResponse;

  @IsString()
  @IsNotEmpty()
  @MaxLength(512)
  challenge: string;
}

export class PasskeyLoginFinishDto {
  @ValidateNested()
  @Type(() => Object)
  response: PasskeyAssertionResponse;

  @IsString()
  @IsNotEmpty()
  @MaxLength(512)
  challenge: string;
}
