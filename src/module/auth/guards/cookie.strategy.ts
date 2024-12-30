// cookie.strategy.ts
import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-cookie';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class CookieStrategy extends PassportStrategy(Strategy, 'cookie') {
    constructor(
        private configService: ConfigService,
        private jwtService: JwtService,
    ) {
        super({
            cookieName: 'auth-cookie',
            signed: false,
            passReqToCallback: true,
        });
    }

    async validate(req: Request, token: string) {
        try {
            const payload = this.jwtService.verify(token, {
                secret: this.configService.get<string>('JWT_SECRET'),
            });
            return { id: payload.id };
        } catch (error) {
            return null;
        }
    }
}
