import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString, Matches } from 'class-validator';

export class ResetPasswordDto {
    @ApiProperty({
        description: 'Reset token sent to the user for password reset',
        example: 'abcdef123456',
    })
    @IsNotEmpty()
    resetToken: string;

    @ApiProperty({
        description: 'New password for the user. Must include at least one letter, one number, and one special character.',
        example: 'NewP@ssw0rd!',
    })
    @IsNotEmpty()
    @IsString()
    @Matches(
        /^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{6,}$/,
        { message: 'Password must be at least 6 characters long, include one letter, one number, and one special character.' }
    )
    newPassword: string;

    @ApiProperty({
        description: 'Confirmation of the new password. Must match the newPassword field.',
        example: 'NewP@ssw0rd!',
    })
    @IsNotEmpty()
    confirmPassword: string;
}
