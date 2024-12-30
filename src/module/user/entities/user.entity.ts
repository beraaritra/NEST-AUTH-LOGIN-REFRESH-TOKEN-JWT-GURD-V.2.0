// user.entity.ts
import { RefreshToken } from 'src/module/auth/entities/refresh-token.entity';
import { ResetToken } from 'src/module/auth/entities/reset-token.entity';
import { VerifyToken } from 'src/module/auth/entities/verify-token.entity';
import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn, UpdateDateColumn, OneToMany } from 'typeorm';

@Entity()
export class User {
    @PrimaryGeneratedColumn()
    id: number;

    @Column()
    firstName: string;

    @Column()
    lastName: string;

    @Column({ nullable: true, unique: true })
    email: string;

    @Column({ nullable: true })
    phoneNumber: string;

    @Column({ nullable: true, select: false })
    password: string;

    @Column({ default: false })
    verifiedUser: boolean;

    @CreateDateColumn()
    createdAt: Date;

    @UpdateDateColumn()
    updatedAt: Date;

    // Relationship with refresh tokens
    @OneToMany(() => RefreshToken, (refreshToken) => refreshToken.user)
    refreshTokens: RefreshToken[];

    // Relationship with reset tokens
    @OneToMany(() => ResetToken, (resetToken) => resetToken.user, { cascade: true })
    resetTokens: ResetToken[];

    // Relationship with verify tokens
    @OneToMany(() => VerifyToken, (verifyToken) => verifyToken.user, { cascade: true })
    verifyTokens: VerifyToken[];
}