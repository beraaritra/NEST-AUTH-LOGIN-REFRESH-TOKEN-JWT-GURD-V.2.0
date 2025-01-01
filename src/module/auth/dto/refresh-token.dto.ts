import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsUUID } from 'class-validator';

export class RefreshTokenDto {
    @ApiProperty({
        description: 'The UUID refresh token used to obtain a new access token',
        example: '123e4567-e89b-12d3-a456-426614174000',
    })
    @IsNotEmpty()
    @IsUUID()
    refreshToken: string;
}
