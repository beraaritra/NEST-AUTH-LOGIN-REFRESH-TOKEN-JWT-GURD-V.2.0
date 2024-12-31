import { Controller, Get, Param, ParseIntPipe, BadRequestException } from '@nestjs/common';
import { UserService } from './user.service';

@Controller('users')
export class UserController {
  constructor(private readonly userService: UserService) { }

  // GET: /users/:id (Fetch user by ID)
  @Get(':id')
  async getUserById(@Param('id', ParseIntPipe) id: number) {
    try {
      const user = await this.userService.findUserById(id);
      return { status: 'success', message: 'User profile fetched successfully by ID.', data: user };
    } catch (error) {
      throw new BadRequestException(error.message || 'Unable to fetch user profile.');
    }
  }

  // GET: /users (Fetch all users)
  @Get()
  async getAllUsers() {
    try {
      const users = await this.userService.findAllUsers();
      return { status: 'success', message: 'All users fetched successfully.', data: users };
    } catch (error) {
      throw new BadRequestException(error.message || 'Unable to fetch users.');
    }
  }
}
