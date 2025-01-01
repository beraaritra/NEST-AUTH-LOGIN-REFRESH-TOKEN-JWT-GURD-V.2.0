import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsString, IsNotEmpty, Length } from 'class-validator';

export class VerifyEmailTokenDto {
    @ApiProperty({
        description: '6-digit verification code sent to the users email',
        example: '123456',
    })
    @IsString()
    @IsNotEmpty()
    @Length(6, 6)
    code: string; // 6-digit code
}
