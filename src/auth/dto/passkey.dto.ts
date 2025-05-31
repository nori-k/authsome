// src/auth/dto/passkey.dto.ts
// 型安全なFIDO2/Passkey DTO定義

import {
  IsString,
  IsNotEmpty,
  IsArray,
  IsOptional,
  ValidateNested,
  IsObject,
} from 'class-validator';
import { Type } from 'class-transformer';

// 依存される側を先に定義
export class PasskeyAttestationResponseInner {
  @IsArray()
  attestationObject: number[];

  @IsArray()
  clientDataJSON: number[];

  @IsOptional()
  @IsArray()
  transports?: string[];
}

export class PasskeyAssertionResponseInner {
  @IsArray()
  authenticatorData: number[];

  @IsArray()
  clientDataJSON: number[];

  @IsArray()
  signature: number[];

  @IsOptional()
  @IsArray()
  userHandle?: number[];
}

// 依存する側を後に定義
export class PasskeyAttestationResponse {
  @IsString()
  @IsNotEmpty()
  id: string;

  @IsArray()
  rawId: number[];

  @ValidateNested()
  @Type(() => PasskeyAttestationResponseInner)
  response: PasskeyAttestationResponseInner;

  @IsString()
  @IsNotEmpty()
  type: string;

  @IsObject()
  clientExtensionResults: Record<string, unknown>;
}

export class PasskeyAssertionResponse {
  @IsString()
  @IsNotEmpty()
  id: string;

  @IsArray()
  rawId: number[];

  @ValidateNested()
  @Type(() => PasskeyAssertionResponseInner)
  response: PasskeyAssertionResponseInner;

  @IsString()
  @IsNotEmpty()
  type: string;

  @IsObject()
  clientExtensionResults: Record<string, unknown>;
}
