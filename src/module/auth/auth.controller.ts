// auth.controller.ts
import { Body, Controller, Post, UseGuards, Req, Get, Put, UnauthorizedException, Request, BadRequestException, InternalServerErrorException, Res, HttpCode, Delete, NotFoundException } from '@nestjs/common';
import { AuthService } from './auth.service';
import { JwtAuthGuard } from './guards/jwt.guard';
import { SignupDto } from './dto/signup.dto';
import { LoginDto } from './dto/login.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { ChangePasswordDto } from './dto/change-password.dto';
import { ForgotpasswordDto } from './dto/forgot-password.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { Response } from 'express';
import { VerifyEmailTokenDto } from './dto/verify-email-token.dto';
import {
    ApiOkResponse,
    ApiOperation,
    ApiCreatedResponse,
    ApiBadRequestResponse,
    ApiInternalServerErrorResponse,
    ApiUnauthorizedResponse,
    ApiBearerAuth,
    ApiNotFoundResponse,
} from '@nestjs/swagger';
import { ResendVerificationCodeDto } from './dto/resend-verification-code.dto';

@Controller('auth')
export class AuthController {
    constructor(private readonly authService: AuthService) { }

    //=====================================FOR SIGNUP====================================//
    @Post('signup')
    @ApiOperation({
        summary: 'Sign up a new user',
        description: 'This endpoint allows the creation of a new user by providing necessary user details such as firstname, lastName, email, and password.'
    })
    @ApiCreatedResponse({
        description: 'User signed up successfully.',
        schema: {
            example: {
                statusCode: 200,
                status: 'success',
                message: 'User signed up successfully, Please verify The email address',
                data: {
                    id: '1',
                    email: 'user@example.com',
                    firstName: 'John',
                    lastName: 'Doe',
                    phoneNumber: '1234567890',
                    verifiedUser: false,
                    createdAt: new Date().toISOString(),
                    updatedAt: new Date().toISOString(),
                    accessToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6OCwiZW1haWwiOiJhcml0cmFiZXJhNjdAZ21haWwuY29tLmluIiwiaWF0IjoxNzM1NzUxMjcxLCJleHAiOjE3MzU3NTQ4NzF9.jL6asmbb0NYhYUMmJemmtclpLYvxinUer6zZwuoKk5U",
                    refreshToken: "0c0f436e-0246-4150-8344-de1078aff975"
                },
            },
        },
    })
    @ApiBadRequestResponse({
        description: 'Signup failed due to validation or other errors.',
        schema: {
            example: {
                statusCode: 400,
                status: 'error',
                message: 'User already exisit same malil / enter 6 char password (Password@123) Like.',
            },
        },
    })
    @ApiInternalServerErrorResponse({
        description: 'Internal server error',
        schema: {
            example: {
                statusCode: 500,
                status: 'error',
                message: 'Internal server error',
            },
        },
    })
    @HttpCode(201) // Explicitly set the response
    async signup(@Body() body: SignupDto) {
        try {
            const user = await this.authService.signup(body);
            return { status: 'success', message: 'User signed up successfully ,Please verify The email address', data: user };
        } catch (error) {
            if (error instanceof UnauthorizedException) { throw error };
            throw new BadRequestException(error.message || 'Signup failed.');
        }
    }

    //========================= FOR GENERATE NEW VERIFICATION CODE ======================//
    @Put('resend-verification-code')
    @ApiOperation({
        summary: 'Resend verification code',
        description: 'This endpoint allows the user to resend the verification code to their Signup email for account verification. It can be used if the original verification code has expired or was not received.'
    })
    @ApiCreatedResponse({
        description: 'Verification code resent successfully.',
        schema: {
            example: {
                statusCode: 200,
                status: 'success',
                message: 'A new verification code has been sent to your email.',
                email: 'user@example.com',
            },
        },
    })
    @ApiBadRequestResponse({
        description: 'Invalid email address or email is already verified.',
        schema: {
            example: {
                statusCode: 400,
                status: 'error',
                message: 'User with this email does not exist / email id already verified.',
            },
        },
    })
    @ApiInternalServerErrorResponse({
        description: 'Internal server error.',
        schema: {
            example: {
                statusCode: 500,
                status: "error",
                message: 'Internal server error',
            },
        },
    })
    @HttpCode(201) // Explicitly set the response
    async resendVerificationCode(@Body() resendVerificationCodeDto: ResendVerificationCodeDto) {
        // console.log('Received email:', resendVerificationCodeDto.email);
        const result = await this.authService.resendVerificationCode(resendVerificationCodeDto.email);
        return {
            status: 'success',
            message: 'A new verification code has been sent to your email.',
            email: result.email,
        };
    }

    //===================================FOR VERIFY OTP===================================//
    @Put('verify-email')
    @ApiOperation({
        summary: 'Verify user email address using a code',
        description: 'This endpoint allows a user to verify their email address by providing the verification code sent to their email. On success, the email is marked as verified.'
    })
    @ApiOkResponse({
        description: 'Email verified successfully.',
        schema: {
            example: {
                statusCode: 200,
                status: 'success',
                message: 'Email verified successfully.',
                data: {
                    email: 'user@example.com',
                    // verificationStatus: 'verified'
                }
            }
        }
    })
    @ApiBadRequestResponse({
        description: 'Invalid verification code or email.',
        schema: {
            example: {
                statusCode: 400,
                status: 'error',
                message: 'The verification code is incorrect or has expired.'
            }
        }
    })
    @ApiInternalServerErrorResponse({
        description: 'Internal server error, something went wrong on the server.',
        schema: {
            example: {
                statusCode: 500,
                status: 'error',
                message: 'An unexpected error occurred while verifying the email.'
            }
        }
    })
    @ApiBearerAuth()
    @HttpCode(200) // Explicitly set the response ☻
    @UseGuards(JwtAuthGuard)
    @ApiBearerAuth('accessToken')
    async verifyEmail(@Request() req, @Body() verifyEmailDto: VerifyEmailTokenDto) {
        const { code } = verifyEmailDto;
        const { email } = req.user; // Extract email from token

        console.log(`Verifying email for email: ${email}, code: ${code}`);

        const result = await this.authService.verifyEmail(email, code);

        return { status: 'success', message: 'Email verified successfully.', data: result };
    }

    //=====================================FOR LOGIN====================================//
    @Post('login')
    @ApiOperation({
        summary: 'Log in a user',
        description: 'This endpoint allows a user to log in by providing their credentials. On success, an access token and refresh token are returned and saved in a secure, HTTP-only cookie.'
    })
    @ApiOkResponse({
        description: 'User logged in successfully.',
        schema: {
            example: {
                statusCode: 200,
                status: 'success',
                message: 'User logged in successfully',
                data: {
                    userId: 2,
                    accessToken: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MiwiaWF0IjoxNzM1NzYxMDIzLCJleHAiOjE3MzU3NjQ2MjN9.rhLZ6ymKWKMpaqV1K30o4yxuD-uG-N7a-37dsHvWruQ',
                    refreshToken: '89af319d-0d7c-4293-a3de-07c08e78c597'
                }
            }
        }
    })
    @ApiBadRequestResponse({
        description: 'Login failed due to invalid credentials or euser not exsit.',
        schema: {
            example: {
                statusCode: 400,
                status: 'error',
                message: 'Invalid credentials provided / user not exist.',
            }
        }
    })
    @ApiInternalServerErrorResponse({
        description: 'Internal server error.',
        schema: {
            example: {
                statusCode: 500,
                status: 'error',
                message: 'Internal server error.'
            }
        }
    })
    @HttpCode(200) // Explicitly set the response ☻
    async login(@Body() loginDto: LoginDto, @Res({ passthrough: true }) res: Response) {
        try {
            const user = await this.authService.login(loginDto);
            // Saved Cookies
            res.cookie('auth-cookie', user.accessToken, { httpOnly: true, secure: true, sameSite: 'strict' });
            return { status: 'success', message: 'User logged in successfully', data: user };
        } catch (error) {
            if (error instanceof UnauthorizedException) { throw error; }
            throw new BadRequestException(error.message || 'Login failed.');
        }
    }

    // ============================ FOR GET PROFILE BY JWT ============================//
    @Get('profile')
    @ApiOperation({
        summary: 'Get user profile by JWT',
        description: 'Fetches the profile of the authenticated user using their JWT token.',
    })
    @ApiOkResponse({
        description: 'Profile retrieved successfully.',
        schema: {
            example: {
                statusCode: 400,
                status: 'success',
                message: 'profile get successfully By JWT',
                data: {
                    id: 2,
                    firstName: 'Aritra',
                    lastName: 'Bera',
                    email: 'aritrabera67@gmail.com',
                    phoneNumber: '1234567890',
                    verifiedUser: true,
                    createdAt: '2025-01-01T19:21:42.324Z',
                    updatedAt: '2025-01-01T19:23:02.472Z',
                },
            },
        },
    })
    @ApiUnauthorizedResponse({
        description: 'Unauthorized request.',
        schema: {
            example: {
                statusCode: 401,
                status: 'error',
                message: 'Unauthorized',
            },
        },
    })
    @ApiBadRequestResponse({
        description: 'Bad Request due to invalid parameters or internal error.',
        schema: {
            example: {
                statusCode: 400,
                status: 'error',
                message: 'Could Not Get Your Profile.',
            },
        },
    })
    @ApiInternalServerErrorResponse({
        description: 'Internal server error.',
        schema: {
            example: {
                statusCode: 500,
                status: 'error',
                message: 'Internal Server Error.',
            },
        },
    })
    @ApiBearerAuth('accessToken')
    @HttpCode(200) // Explicitly set the response ☻
    @UseGuards(JwtAuthGuard)
    async getProfile(@Req() req: any) {
        try {
            const user = await this.authService.getProfile(req.user.id);
            return { status: 'success', message: 'profile get successfully By JWT', data: user };
        } catch (error) {
            if (error instanceof UnauthorizedException) { throw error; }
            throw new BadRequestException(error.message || 'Could Not Get Your Profile.');
        }
    }

    // ========================= FOR UPDATE PASSWORD BY JWT ==========================//
    @Put('update-password')
    @ApiOperation({ summary: 'Update password using JWT' })
    @ApiOperation({
        summary: 'Update password using JWT',
        description: 'This endpoint allows the authenticated user to update their password by providing their newPassword  and the new confirmNewPassword.'
    })
    @ApiOkResponse({
        description: 'Password updated successfully.',
        schema: {
            example: {
                statusCode: 200,
                status: 'success',
                message: 'Password updated successfully'
            }
        }
    })
    @ApiBadRequestResponse({
        description: 'Password update failed due to validation or other errors.',
        schema: {
            example: {
                statusCode: 400,
                status: 'error',
                message: 'Password update failed due to validation errors or incorrect input.'
            }
        }
    })
    @ApiInternalServerErrorResponse({
        description: 'internal Server Error.',
        schema: {
            example: {
                statusCode: 500,
                status: 'error',
                message: 'An unexpected error occurred while updating the password.'
            }
        }
    })
    @UseGuards(JwtAuthGuard)
    @ApiBearerAuth('accessToken')
    @HttpCode(200) // Explicitly set the response
    async updatePassword(@Body() changePasswordDto: ChangePasswordDto, @Request() req) {
        try {
            const userId = req.user.id; // Extract user from the token payload
            // console.log("================", req.user, "==============");
            if (!userId) {
                throw new UnauthorizedException('User not found in request.');
            }

            await this.authService.updatePassword(
                userId,
                changePasswordDto.newPassword,
                changePasswordDto.confirmNewPassword,
            );

            return { status: 'success', message: 'Password updated successfully', };
        } catch (error) {
            if (error instanceof UnauthorizedException) {
                throw error
            }
            else if (error instanceof BadRequestException) {
                throw error;
            } else {
                throw new InternalServerErrorException('An unexpected error occurred while updating the password.');
            }
        }
    }

    // ============================ FOR REFRESHING ACCESS TOKEN ========================//
    @Post('refresh-token')
    @ApiOperation({
        summary: 'Refresh access token using a refresh token',
        description: 'This endpoint allows a user to refresh their access token by providing a valid refresh token.'
    })
    @ApiOkResponse({
        description: 'Token refreshed successfully.',
        schema: {
            example: {
                statusCode: 200,
                status: 'success',
                message: 'Token refreshed',
                data: {
                    accessToken: 'new-access-token',
                    refreshToken: 'new-refresh-token'
                }
            }
        }
    })
    @ApiUnauthorizedResponse({
        description: 'Invalid refresh token.',
        schema: {
            example: {
                statusCode: 401,
                status: 'error',
                message: 'Invalid refresh token'
            }
        }
    })
    @ApiInternalServerErrorResponse({
        description: 'internal Server Error.',
        schema: {
            example: {
                statusCode: 500,
                status: 'error',
                message: 'internal Server Error.'
            }
        }
    })
    @HttpCode(200) // Explicitly set the response
    async refreshAccessToken(@Body() refreshTokenDto: RefreshTokenDto) {
        try {
            const { refreshToken } = refreshTokenDto;
            const tokens = await this.authService.refreshAccessToken(refreshToken);
            return { status: 'success', message: 'Token refreshed', data: tokens };
        } catch (error) {
            throw new UnauthorizedException(error.message || 'Invalid refresh token');
        }
    }

    // ============================== FOR FORGOT PASSWORD ============================//
    @Post('forgot-password')
    @ApiOperation({
        summary: 'Trigger forgot password process',
        description: 'This endpoint triggers the forgot password process. If the user exists, they will receive an email with instructions to reset their password.'
    })
    @ApiOkResponse({
        description: 'Forgot password process if user exists.',
        schema: {
            example: {
                statusCode: 200,
                status: 'success',
                message: 'If this user exists, they will receive an email with reset instructions.'
            }
        }
    })
    @ApiInternalServerErrorResponse({
        description: 'Internal Server Error.',
        schema: {
            example: {
                statusCode: 500,
                status: 'error',
                message: 'Internal Server Error.'
            }
        }
    })
    @HttpCode(200) // Explicitly set the response
    async forgotPassword(@Body() forgotpasswordDto: ForgotpasswordDto) {
        await this.authService.forgotPassword(forgotpasswordDto.email)
        return { status: "Success", message: 'If this User exists, they will recive an email' }
    }

    // ============================ FOR RESET PASSWORD ============================//
    @Post('reset-password')
    @ApiOperation({
        summary: 'Reset password using reset token',
        description: 'This endpoint allows a user to reset their password by providing a valid reset token and new password.'
    })
    @ApiOkResponse({
        description: 'Password reset successfully.',
        schema: {
            example: {
                statusCode: 200,
                status: 'success',
                message: 'Password has been reset successfully.'
            }
        }
    })
    @ApiBadRequestResponse({
        description: 'Invalid reset token or mismatched passwords.',
        schema: {
            example: {
                statusCode: 400,
                status: 'error',
                message: 'Invalid reset token or the new password and confirmation do not match.'
            }
        }
    })
    @ApiInternalServerErrorResponse({
        description: 'Internal Server Error.',
        schema: {
            example: {
                statusCode: 500,
                status: 'error',
                message: 'Internal Server Error.'
            }
        }
    })
    @HttpCode(200) // Explicitly set the response
    async resetPassword(@Body() resetPasswordDto: ResetPasswordDto) {
        await this.authService.resetPassword(
            resetPasswordDto.resetToken,
            resetPasswordDto.newPassword,
            resetPasswordDto.confirmPassword
        )
        return { status: "Success", message: 'Password has been reset successfully.' };
    }

    // // ============================ FOR LOGOUT ACCOUNT ============================//
    @Delete('logout')
    @ApiOperation({
        summary: 'Log out a user',
        description: 'This endpoint allows a user to log out by invalidating their access token.'
    })
    @ApiOkResponse({
        description: 'User logged out successfully.',
        schema: {
            example: {
                statusCode: 200,
                status: 'success',
                message: 'User logged out successfully.'
            }
        }
    })
    @ApiUnauthorizedResponse({
        description: 'User is not authenticated or token is invalid.',
        schema: {
            example: {
                statusCode: 401,
                status: 'error',
                message: 'Unauthorized.'
            }
        }
    })
    @ApiNotFoundResponse({
        description: 'No active refresh token found for the user.',
        schema: {
            example: {
                statusCode: 404,
                status: 'error',
                message: 'No active refresh token found for the user.'
            }
        }
    })
    @ApiInternalServerErrorResponse({
        description: 'Internal Server Error.',
        schema: {
            example: {
                statusCode: 500,
                status: 'error',
                message: 'Internal server error.'
            }
        }
    })
    @UseGuards(JwtAuthGuard)
    @ApiBearerAuth('accessToken')
    @HttpCode(200) // Explicitly set the response
    async logout(@Req() req) {
        const userId = req.user.id; // Assuming JWT Guard attaches user details to the request
        try {
            await this.authService.logout(userId);
            return {
                statusCode: 200,
                status: 'success',
                message: 'User logged out successfully.'
            };
        } catch (error) {
            if (error instanceof NotFoundException) {
                return {
                    statusCode: 404,
                    status: 'error',
                    message: 'No active refresh token found for the user.'
                };
            }
            throw new InternalServerErrorException('Internal server error');
        }
    }
}