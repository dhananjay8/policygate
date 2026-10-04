import { IsIn, IsNotEmpty, IsObject, IsOptional, IsString } from 'class-validator';

export class PrincipalDto {
  @IsString()
  @IsNotEmpty()
  id!: string;

  @IsIn(['USER', 'AGENT', 'SERVICE'])
  type!: 'USER' | 'AGENT' | 'SERVICE';

  @IsOptional()
  authenticated?: boolean = true;

  @IsOptional()
  @IsObject()
  metadata?: Record<string, unknown>;
}

export class AuthorizeRequestDto {
  @IsObject()
  principal!: PrincipalDto;

  @IsString()
  @IsNotEmpty()
  action!: string;

  @IsString()
  @IsNotEmpty()
  resource!: string;

  @IsOptional()
  @IsString()
  accountId?: string;

  @IsOptional()
  @IsObject()
  variables?: Record<string, unknown>;

  @IsOptional()
  @IsObject()
  requestContext?: Record<string, unknown>;
}
