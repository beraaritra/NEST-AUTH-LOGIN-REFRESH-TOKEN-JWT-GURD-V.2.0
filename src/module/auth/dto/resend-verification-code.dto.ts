import { IsEmail } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class ResendVerificationCodeDto {
    @ApiProperty({
        description: 'Email address of the user requesting a new verification code',
        example: 'user@example.com',
    })
    @IsEmail()
    email: string;
}
