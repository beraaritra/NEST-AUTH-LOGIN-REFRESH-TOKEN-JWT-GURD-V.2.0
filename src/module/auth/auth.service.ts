// auth.service.ts
import { Injectable, BadRequestException, UnauthorizedException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from '../user/entities/user.entity';
import { RefreshToken } from './entities/refresh-token.entity';
import { ResetToken } from './entities/reset-token.entity';
import { SignupDto } from './dto/signup.dto';
import { LoginDto } from './dto/login.dto';
import { JwtService } from '@nestjs/jwt';
import { MailService } from '../service/mail.service';
import * as bcrypt from 'bcrypt';
import { v4 as uuidv4 } from 'uuid';
import { nanoid } from 'nanoid';
import { VerifyToken } from './entities/verify-token.entity';

@Injectable()
export class AuthService {
    constructor(
        @InjectRepository(User)
        private readonly userRepository: Repository<User>,
        @InjectRepository(RefreshToken)
        private readonly refreshTokenRepository: Repository<RefreshToken>,
        @InjectRepository(ResetToken)
        private readonly resetTokenRepository: Repository<ResetToken>,
        @InjectRepository(VerifyToken)
        private readonly verifyTokenRepository: Repository<VerifyToken>,
        private readonly jwtService: JwtService,
        private readonly mailService: MailService,
    ) { }

    // ============================== Helper function to generate refresh token ============================//
    private generateRefreshToken(): string {
        return uuidv4();
    }

    // ========================================== For Signup Service========================================//
    async signup(signupDto: SignupDto) {

        const { email, password, confirmPassword, firstName, lastName, phoneNumber } = signupDto;

        // Check is user already existing or not
        const user = await this.userRepository.findOne({
            where: { email },
            select: ['id', 'email', 'password', 'firstName', 'lastName', 'phoneNumber']
        });
        if (user) throw new BadRequestException('User With This Email already exists');

        // Check password match 
        if (password !== confirmPassword) throw new BadRequestException('Passwords do not match.');

        // Hash password 
        const hashedPassword = await bcrypt.hash(password, 10);

        // create the new user in the database
        const newUser = this.userRepository.create({
            email,
            password: hashedPassword,
            firstName,
            lastName,
            phoneNumber,
            verifiedUser: false,
        });

        // saved the new user in the database
        const savedUser = await this.userRepository.save(newUser);

        // Generate access token and refresh token
        const accessToken = this.jwtService.sign({ id: savedUser.id, email: savedUser.email });
        const refreshToken = this.generateRefreshToken();

        // Store refresh token in the database
        await this.storeRefreshToken(refreshToken, savedUser);

        // Generate 6-digit code and save to verify code
        const code = Math.floor(100000 + Math.random() * 900000).toString(); // Random 6-digit code
        const expiryDate = new Date(Date.now() + 10 * 60 * 1000); // 10-minute expiry

        // create the verification token in the database
        const verifyToken = this.verifyTokenRepository.create({
            code,
            user: savedUser,
            expiryDate,
        });

        // saved the verification token in database
        await this.verifyTokenRepository.save(verifyToken);

        // Create a Email body for verification code 
        const emailBody =
            `<p>Hi ${firstName},</p>
            <p>Your verification code is: <b>${code}</b>.</p>
            <p>This code is valid for 10 minutes.</p>`;

        // Send email verification code
        await this.mailService.sendMail(email, 'Verify Your Email', emailBody);

        // Return the user signup data
        return {
            id: savedUser.id,
            email: savedUser.email,
            firstName: savedUser.firstName,
            lastName: savedUser.lastName,
            phoneNumber: savedUser.phoneNumber,
            verifiedUser: savedUser.verifiedUser,
            accessToken,
            refreshToken
        }
    }

    // =========================== For Generate New Verification Code Service===============================//
    async resendVerificationCode(email: string): Promise<{ email: string }> {
        // Check if the user exists
        const user = await this.userRepository.findOne({
            where: { email },
            select: ['id', 'email', 'password', 'firstName', 'lastName', 'phoneNumber']
        });
        if (!user) {
            throw new BadRequestException('User with this email does not exist.');
        }

        if (user.verifiedUser) {
            throw new BadRequestException('Email is already verified.');
        }

        // Generate a new verification code
        const code = Math.floor(100000 + Math.random() * 900000).toString();
        const expiryDate = new Date(Date.now() + 10 * 60 * 1000); // 10-minute expiry

        // Create or update the verification token in the database
        let verifyToken = await this.verifyTokenRepository.findOne({
            where: { user: { id: user.id } },
        });

        if (verifyToken) {
            // Update existing token
            verifyToken.code = code;
            verifyToken.expiryDate = expiryDate;
            await this.verifyTokenRepository.save(verifyToken);
        } else {
            // Create a new token
            verifyToken = this.verifyTokenRepository.create({
                code,
                user,
                expiryDate,
            });
            await this.verifyTokenRepository.save(verifyToken);
        }

        // Send the new verification code to the user's email
        const emailBody =
            `<p>Hi ${user.firstName},</p>
           <p>Your new verification code is: <b>${code}</b>.</p>
           <p>This code is valid for 10 minutes.</p>`;
        await this.mailService.sendMail(user.email, 'Verify Your Email', emailBody);

        return { email: user.email };
    }

    // ====================================== For Verify OTP Service ======================================//
    async verifyEmail(email: string, code: string): Promise<{ email: string }> {

        // Find the user by email
        const user = await this.userRepository.findOne({ where: { email } });
        if (!user) {
            throw new UnauthorizedException('Invaalid token not found.');
        }

        // Find the verification token for the user
        const verifyToken = await this.verifyTokenRepository.findOne({
            where: { user: { id: user.id }, code },
        });

        if (!verifyToken) {
            throw new BadRequestException('Invalid verification code.');
        }

        if (new Date() > verifyToken.expiryDate) {
            throw new BadRequestException('Verification code has expired. Please request a new code.');
        }

        // Check if the token has expired
        if (new Date() > verifyToken.expiryDate) {
            throw new BadRequestException('Verification code has expired.');
        }

        // Mark user as verified
        user.verifiedUser = true;
        await this.userRepository.save(user);

        // Send a welcome email
        const welcomeEmailBody = `<p>Welcome to our Hello Pay, ${user.firstName}!</p>`;
        await this.mailService.sendMail(user.email, 'Welcome!', welcomeEmailBody);

        // Delete the verification token
        await this.verifyTokenRepository.delete({ id: verifyToken.id });

        return { email: user.email };
    }

    // =========================================== For Login Service========================================//
    async login({ email, password }: LoginDto) {

        // Find the user by mail address
        const user = await this.userRepository.findOne({ where: { email }, select: ['id', 'email', 'verifiedUser', 'password'] });

        // Validation Check
        if (!user || !(await bcrypt.compare(password, user.password))) {
            throw new UnauthorizedException('User not Exits or invalid credentials');
        }

        // Check if user is verified or not
        if (!user.verifiedUser) { throw new UnauthorizedException('User not verified') }

        // Generate access token and refresh token
        const accessToken = this.jwtService.sign({ id: user.id });
        const refreshToken = this.generateRefreshToken();

        // Store refresh token in the database
        await this.storeRefreshToken(refreshToken, user);

        return { userId: user.id, accessToken, refreshToken };
    }

    // ======================================= For Get Profile By JWT Service===============================//
    async getProfile(userId: number) {
        const user = await this.userRepository.findOne({
            where: { id: userId },
            select: ['id', 'email', 'password', 'verifiedUser', 'firstName', 'lastName', 'createdAt', 'updatedAt'],
        });
        if (!user) {
            throw new UnauthorizedException('User not found');
        }
        const { password, ...profile } = user;
        return profile;
    }

    // ================================= For Update Password By JWT Service=================================//
    async updatePassword(userId: number, newPassword: string, confirmNewPassword: string) {
        // Find the user by ID and select the password
        const user = await this.userRepository.findOne({
            where: { id: userId },
            select: ['id', 'password'],
        });

        if (!user) { throw new UnauthorizedException('User not found.') };

        // Verify if the confirmPassword and confirmNewPassword match
        if (newPassword !== confirmNewPassword) {
            throw new BadRequestException('New password and confirm password do not match.');
        }

        // Hash the new password
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        // Update the user's password
        user.password = hashedPassword;
        await this.userRepository.save(user);
    }

    // ======================================== For Refreshing Access Token =================================//
    async refreshAccessToken(refreshToken: string) {
        // Find the refresh token in the database
        const tokenRecord = await this.refreshTokenRepository.findOne({ where: { token: refreshToken }, relations: ['user'] });

        if (!tokenRecord) {
            throw new UnauthorizedException('Invalid refresh token');
        }

        // Check if the refresh token has expired
        if (new Date() > tokenRecord.expiryDate) {
            throw new UnauthorizedException('Refresh token has expired. Please log in again.');
        }

        const { user } = tokenRecord;

        // Generate a new Access Token
        const newAccessToken = this.jwtService.sign({ id: user.id });

        // Generate a new Refresh Token
        const newRefreshToken = this.generateRefreshToken();

        // Store the new refresh token in the database
        await this.storeRefreshToken(newRefreshToken, user);

        // Return the new tokens
        return {
            accessToken: newAccessToken,
            refreshToken: newRefreshToken,
        };
    }

    // ========================================= For Forgot Password Service =================================//
    async forgotPassword(email: string,) {
        const user = await this.userRepository.findOne({
            where: { email },
            select: ['id', 'email',]
        });

        // Set the expiration date
        const expiryDate = new Date();
        expiryDate.setHours(expiryDate.getHours() + 1);

        // User validation Check
        if (!user) {
            throw new UnauthorizedException('Invalid email or User Not exist');
        }

        // Save The New Generate Reset Token in DB
        else {
            const resetToken = nanoid(64);

            // Create a new reset token record in the database and set the expiration date
            const newResetToken = this.resetTokenRepository.create({ token: resetToken, user, expiryDate });

            // Remove the existing refresh token for the user if it exists
            const existingToken = await this.resetTokenRepository.findOne({ where: { user } });
            if (existingToken) {
                await this.resetTokenRepository.delete({ id: existingToken.id });
            }

            // Save the new reset token in the database with the expiration date and user reference
            await this.resetTokenRepository.save(newResetToken);

            // Construct the reset password link
            const resetPasswordUrl = `${process.env.FRONTEND_URL}/reset-password?token=${resetToken}`;

            // Send the reset password email
            const subject = "Password Reset Request";
            const html = `
            <p>Hello,</p>
            <p>We received a request to reset your password. Please use the link below to set a new password:</p>
            <a href="${resetPasswordUrl}">Reset Password</a>
            <p>This link will expire in 1 hour.</p>
            <p>If you did not request a password reset, please ignore this email.</p> `;

            await this.mailService.sendMail(user.email, subject, html);
        }
    }

    // ========================================= For Reset Paasword  Service =================================//
    async resetPassword(resetToken: string, newPassword: string, confirmPassword: string) {
        // Validate the reset token
        const token = await this.resetTokenRepository.findOne({
            where: { token: resetToken },
            relations: ['user'],
        });

        if (!token) {
            throw new UnauthorizedException('Invalid reset password Link.');
        }

        // Check if the token has expired
        if (new Date() > token.expiryDate) {
            await this.resetTokenRepository.delete({ id: token.id }); // Clean up expired token
            throw new UnauthorizedException('Reset token has expired.');
        }

        const user = token.user;

        // Verify if the passwords match
        if (newPassword !== confirmPassword) {
            throw new BadRequestException('New password and confirm password do not match.');
        }

        // Hash the new password
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        //  Update the user's password in the database
        user.password = hashedPassword;
        await this.userRepository.save(user);

        //  Delete the used reset token
        await this.resetTokenRepository.delete({ id: token.id });

        // Send a success email to the user
        const subject = "Password Reset Successful";
        const html = `
          <p>Hello ${user.firstName},</p>
          <p>Your password has been reset successfully. If you did not perform this action, please contact support immediately.</p>
          <p>Thank you,</p>
          <p>The Team</p>  `;

        await this.mailService.sendMail(user.email, subject, html);
    }

    // ============================== For Refresh Token Generate and Save Service ============================//
    async generateuserToken(userId: number) {
        const refreshToken = uuidv4();
        return { refreshToken };
    }
    async storeRefreshToken(token: string, user: User) {
        // Remove the existing refresh token for the user if it exists
        await this.refreshTokenRepository.delete({ user: { id: user.id } });

        // Calculate the expiration date for the new refresh token
        const expiryDate = new Date();
        expiryDate.setDate(expiryDate.getDate() + 7);

        // Create a new refresh token entity
        const newRefreshToken = this.refreshTokenRepository.create({
            token,
            user,
            expiryDate,
        });

        // Save the new refresh token in the database
        await this.refreshTokenRepository.save(newRefreshToken);
    }
}