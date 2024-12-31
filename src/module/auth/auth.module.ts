// auth.module.ts
import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { MailModule } from '../service/mail.module';
import { JwtModule } from '@nestjs/jwt';
import { JwtStrategy } from '../auth/guards/jwt.strategy';
import { CookieStrategy } from '../auth/guards/cookie.strategy';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { User } from '../user/entities/user.entity';
import { RefreshToken } from './entities/refresh-token.entity';
import { ResetToken } from './entities/reset-token.entity';
import { VerifyToken } from './entities/verify-token.entity';

@Module({
    imports: [
        TypeOrmModule.forFeature([User, RefreshToken, ResetToken, VerifyToken]),
        MailModule,
        JwtModule.registerAsync({
            imports: [ConfigModule],
            inject: [ConfigService],
            useFactory: async (configService: ConfigService) => ({
                secret: configService.get<string>('JWT_SECRET'),
                signOptions: { expiresIn: configService.get<string>('JWT_EXPIRES_IN') },
            }),
        })
    ],
    providers: [AuthService, JwtStrategy, CookieStrategy],
    controllers: [AuthController],
})
export class AuthModule { }
