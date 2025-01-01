import { IsString, IsEmail, Matches, IsNotEmpty, MinLength } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class SignupDto {
  @ApiProperty({
    description: 'Unique email address for the user',
    example: 'john.doe@example.com',
  })
  @IsEmail({}, { message: 'Please provide a valid email address.' })
  email: string;

  @ApiProperty({
    description: 'Password for the user. Must include at least one letter, one number, and one special character.',
    example: 'Passw0rd!',
  })
  @IsString()
  @IsNotEmpty()
  @Matches(
    /^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{6,}$/,
    { message: 'Password must be at least 6 characters long, include one letter, one number, and one special character.' }
  )
  password: string;

  // @ApiProperty({
  //   description: 'Confirmation of the password. Must match the password field.',
  //   example: 'Passw0rd!',
  // })
  // @IsNotEmpty()
  // @MinLength(6)
  // confirmPassword: string;

  @ApiProperty({
    description: 'First name of the user',
    example: 'John',
  })
  @IsString()
  firstName: string;

  @ApiProperty({
    description: 'Last name of the user',
    example: 'Doe',
  })
  @IsString()
  lastName: string;

  @ApiProperty({
    description: 'Phone number of the user',
    example: '+1234567890',
  })
  @IsString()
  phoneNumber: string;
}
