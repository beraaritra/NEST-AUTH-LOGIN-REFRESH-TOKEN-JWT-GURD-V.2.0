// change-password.dto.ts
import { IsNotEmpty, IsString, Matches, MinLength } from 'class-validator';

export class ChangePasswordDto {

    @IsNotEmpty()
    @IsString()
    @Matches(/^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{6,}$/, {
        message:
            'Password must be at least 6 characters long, include one letter, one number, and one special character.',
    })
    newPassword: string;

    @IsNotEmpty()
    @IsString()
    confirmNewPassword: string;
}
