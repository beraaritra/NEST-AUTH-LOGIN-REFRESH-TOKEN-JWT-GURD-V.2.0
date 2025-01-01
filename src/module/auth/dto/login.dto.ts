// login.dto.ts
import { IsEmail, IsNotEmpty, IsString } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';


export class LoginDto {
  @ApiProperty({
    description: 'Email address of the user',
    example: 'john.doe@example.com',
  })
  @IsEmail({}, { message: 'Please provide a valid email address.' })
  email: string;

  @ApiProperty({
    description: 'Password of the user',
    example: 'Passw0rd!',
  })
  @IsNotEmpty()
  @IsString({ message: 'Password is required and must be a string.' })
  password: string;
}