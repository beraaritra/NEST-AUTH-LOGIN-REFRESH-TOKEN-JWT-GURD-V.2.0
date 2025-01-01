import { Injectable, InternalServerErrorException, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from './entities/user.entity';


@Injectable()
export class UserService {
    constructor(
        @InjectRepository(User)
        private readonly userRepository: Repository<User>,
    ) { }

    // ========================================== For Fetch User By Id Service========================================//
    async findUserById(userId: number): Promise<User> {
        try {
            const user = await this.userRepository.findOne({ where: { id: userId } });

            if (!user) {
                throw new NotFoundException(`User with ID ${userId} not found.`);
            }

            return user;
        } catch (error) {
            if (error instanceof NotFoundException) {
                throw error;
            }
            throw new InternalServerErrorException('An error occurred while fetching the user data.');
        }
    }

    // ========================================== For Fetch All User Service========================================//
    async findAllUsers(): Promise<User[]> {
        try {
            const users = await this.userRepository.find();
            return users;
        } catch (error) {
            throw new InternalServerErrorException('An error occurred while fetching the user list.');
        }
    }
}
