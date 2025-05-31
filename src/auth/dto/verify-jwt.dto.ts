import { IsString } from 'class-validator';

export class VerifyJwtDto {
  @IsString()
  token: string;
}
