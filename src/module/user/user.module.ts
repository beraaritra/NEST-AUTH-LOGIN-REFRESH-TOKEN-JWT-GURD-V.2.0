import { Module } from '@nestjs/common';
import { UserService } from './user.service';
import { UserController } from './user.controller';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from '../user/entities/user.entity';  
 

@Module({
  imports: [TypeOrmModule.forFeature([User])], // Import User entity and AuthModule
  providers: [UserService],
  controllers: [UserController],
})
export class UserModule { }
