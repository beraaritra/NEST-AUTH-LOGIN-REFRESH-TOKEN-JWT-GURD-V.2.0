import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString, Matches, MinLength } from 'class-validator';

export class ChangePasswordDto {

    @ApiProperty({
        description: 'New password for the user. Must include at least one letter, one number, and one special character.',
        example: 'NewP@ssw0rd',
    })
    @IsNotEmpty()
    @IsString()
    @Matches(/^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{6,}$/, {
        message:
            'Password must be at least 6 characters long, include one letter, one number, and one special character.',
    })
    newPassword: string;

    @ApiProperty({
        description: 'Confirmation of the new password. Must match the new password field.',
        example: 'NewP@ssw0rd',
    })
    @IsNotEmpty()
    @IsString()
    confirmNewPassword: string;
}