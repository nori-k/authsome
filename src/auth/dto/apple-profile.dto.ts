import { IsString, IsEmail } from 'class-validator';

// src/auth/dto/apple-profile.dto.ts
export class AppleProfileDto {
  @IsString()
  id: string;

  @IsEmail()
  email: string;
}

export function toAppleProfileDto(profile: unknown): AppleProfileDto {
  if (
    typeof profile === 'object' &&
    profile !== null &&
    'id' in profile &&
    'email' in profile
  ) {
    return {
      id: String((profile as { id: unknown }).id),
      email: String((profile as { email: unknown }).email),
    };
  }
  throw new Error('Invalid Apple profile');
}
