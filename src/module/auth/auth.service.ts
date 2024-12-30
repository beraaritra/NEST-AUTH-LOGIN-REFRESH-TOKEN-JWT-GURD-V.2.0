// auth.service.ts
import { Injectable, BadRequestException, UnauthorizedException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from '../user/entities/user.entity';
import { RefreshToken } from './entities/refresh-token.entity';
import { SignupDto } from './dto/signup.dto';
import { LoginDto } from './dto/login.dto';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { v4 as uuidv4 } from 'uuid';

@Injectable()
export class AuthService {
    constructor(
        @InjectRepository(User)
        private readonly userRepository: Repository<User>,
        @InjectRepository(RefreshToken)
        private readonly refreshTokenRepository: Repository<RefreshToken>,
        private readonly jwtService: JwtService,
    ) { }

    // ==============================Helper function to generate refresh token ============================//
    private generateRefreshToken(): string {
        return uuidv4();
    }

    // ======================================== For Signup Service========================================//
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

        const newUser = this.userRepository.create({
            email,
            password: hashedPassword,
            firstName,
            lastName,
            phoneNumber,
            verifiedUser: false,
        });
        const savedUser = await this.userRepository.save(newUser);

        // Generate access token and refresh token
        const accessToken = this.jwtService.sign({ id: savedUser.id });
        const refreshToken = this.generateRefreshToken();

        // Store refresh token in the database
        await this.storeRefreshToken(refreshToken, savedUser);

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

    // ======================================== For Login Service========================================//
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

    // ================================== For Get Profile By JWT Service===============================//
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

    // =============================== For Update Password By JWT Service=================================//
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

    // =================================== For Refresh Token Service ========================================//
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