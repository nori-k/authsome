import { IsString, IsEmail, IsOptional } from 'class-validator';

export class GoogleProfileDto {
  @IsString()
  id: string;

  @IsEmail()
  email: string;

  @IsOptional()
  @IsString()
  displayName?: string;

  @IsOptional()
  @IsString()
  photoUrl?: string;
}

function isGoogleProfile(obj: unknown): obj is {
  id: string;
  emails: { value: string }[];
  displayName?: string;
  photos?: { value: string }[];
} {
  if (!isObjectWithIdAndEmails(obj)) return false;
  const o = obj as {
    id: string;
    emails: unknown[];
    displayName?: unknown;
    photos?: unknown;
  };
  if (!isValidEmailObject(o.emails[0])) return false;
  if (!isValidDisplayName(o.displayName)) return false;
  if (!isValidPhotos(o.photos)) return false;
  return true;
}

function isObjectWithIdAndEmails(obj: unknown): obj is {
  id: string;
  emails: unknown[];
  displayName?: unknown;
  photos?: unknown;
} {
  if (typeof obj !== 'object' || obj === null) return false;
  const o = obj as Record<string, unknown>;
  return (
    typeof o.id === 'string' && Array.isArray(o.emails) && o.emails.length > 0
  );
}

function isValidEmailObject(obj: unknown): obj is { value: string } {
  return (
    typeof obj === 'object' &&
    obj !== null &&
    'value' in obj &&
    typeof (obj as { value: unknown }).value === 'string'
  );
}

function isValidDisplayName(val: unknown): boolean {
  return typeof val === 'undefined' || typeof val === 'string';
}

function isValidPhotos(val: unknown): boolean {
  if (typeof val === 'undefined') return true;
  if (!Array.isArray(val) || val.length === 0) return false;
  return isValidPhotoObject(val[0]);
}

function isValidPhotoObject(obj: unknown): obj is { value: string } {
  return (
    typeof obj === 'object' &&
    obj !== null &&
    'value' in obj &&
    typeof (obj as { value: unknown }).value === 'string'
  );
}

export function toGoogleProfileDto(profile: unknown): GoogleProfileDto {
  if (isGoogleProfile(profile)) {
    return {
      id: profile.id,
      email: profile.emails[0].value,
      displayName: profile.displayName,
      photoUrl: profile.photos?.[0]?.value,
    };
  }
  throw new Error('Invalid Google profile');
}
