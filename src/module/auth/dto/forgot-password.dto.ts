import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty } from 'class-validator';

export class ForgotpasswordDto {
    @ApiProperty({
        description: 'Email address of the user requesting a password reset',
        example: 'user@example.com',
    })
    @IsNotEmpty()
    email: string;
}
