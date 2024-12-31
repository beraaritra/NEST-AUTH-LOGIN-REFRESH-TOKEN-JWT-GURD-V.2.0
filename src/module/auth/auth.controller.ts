// auth.controller.ts
import { Body, Controller, Post, UseGuards, Req, Get, Put, UnauthorizedException, Request, BadRequestException, InternalServerErrorException, Res, HttpCode } from '@nestjs/common';
import { AuthService } from './auth.service';
import { JwtAuthGuard } from './guards/jwt.guard';
import { SignupDto } from './dto/signup.dto';
import { LoginDto } from './dto/login.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { ChangePasswordDto } from './dto/change-password.dto';
import { ForgotpasswordDto } from './dto/forgot-password.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { Response } from 'express';

@Controller('auth')
export class AuthController {
    constructor(private readonly authService: AuthService) { }

    //=====================================FOR SIGNUP====================================//
    @Post('signup')
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

    //=====================================FOR LOGIN====================================//
    @Post('login')
    @HttpCode(200) // Explicitly set the response
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
    @UseGuards(JwtAuthGuard)
    @Get('profile')
    @HttpCode(200) // Explicitly set the response
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
    @UseGuards(JwtAuthGuard)
    @Put('update-password')
    @HttpCode(201) // Explicitly set the response
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
    @HttpCode(201)
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
    @HttpCode(201) // Explicitly set the response
    async forgotPassword(@Body() forgotpasswordDto: ForgotpasswordDto) {
        await this.authService.forgotPassword(forgotpasswordDto.email)
        return { status: "Success", message: 'If this User exists, they will recive an email' }
    }

    // ============================ FOR RESET PASSWORD ============================//
    @Post('reset-password')
    @HttpCode(201) // Explicitly set the response
    async resetPassword(@Body() resetPasswordDto: ResetPasswordDto) {
        await this.authService.resetPassword(
            resetPasswordDto.resetToken,
            resetPasswordDto.newPassword,
            resetPasswordDto.confirmPassword
        )
        return { status: "Success", message: 'Password has been reset successfully.' };
    }
}