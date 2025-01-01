import { Controller, Get, Param, ParseIntPipe, BadRequestException } from '@nestjs/common';
import { UserService } from './user.service';
import { ApiInternalServerErrorResponse, ApiNotFoundResponse, ApiOkResponse, ApiOperation, ApiTags } from '@nestjs/swagger';

@Controller('users')
export class UserController {
  constructor(private readonly userService: UserService) { }

  // ========================================== FOR FETCH USER BY ID ========================================//
  @ApiOperation({
    summary: 'Fetch user data by ID',
    description: 'This endpoint retrieves the details of a user using their unique ID. If the user exists, it returns their personal details, including their name, email, phone number, and account status. If the user is not found, a NotFoundException will be thrown.'
  })
  @ApiOkResponse({
    description: 'User profile fetched successfully.',
    schema: {
      example: {
        status: 'success',
        message: 'User profile fetched successfully by ID.',
        data: {
          id: 1,
          firstName: 'Aritra',
          lastName: 'Bera',
          email: 'aritrabera78@gmail.com',
          phoneNumber: '1234567890',
          verifiedUser: true,
          createdAt: '2025-01-01T19:19:26.392Z',
          updatedAt: '2025-01-01T21:33:14.693Z'
        }
      }
    }
  })
  @ApiNotFoundResponse({
    description: 'User not found with the given ID.',
    schema: {
      example: {
        statusCode: 400,
        status: 'error',
        message: 'User with ID 1 not found.'
      }
    }
  })
  @ApiInternalServerErrorResponse({
    description: 'Unexpected error occurred while fetching the user data.',
    schema: {
      example: {
        statusCode: 500,
        status: 'error',
        message: 'Internal Server error.'
      }
    }
  })
  @Get(':id')
  async getUserById(@Param('id', ParseIntPipe) id: number) {
    try {
      const user = await this.userService.findUserById(id);
      return { status: 'success', message: 'User profile fetched successfully by ID.', data: user };
    } catch (error) {
      throw new BadRequestException(error.message || 'Unable to fetch user profile.');
    }
  }

  // ========================================== FOR FETCH ALL USER ========================================//
  @ApiOperation({
    summary: 'Fetch all users',
    description: 'This endpoint retrieves a list of all users in the system. It returns detailed information about each user, including their personal details such as first name, last name, email, phone number, account verification status, and account creation/update timestamps. The data returned is an array of user objects.'
  })
  @ApiOkResponse({
    description: 'Successfully retrieved all users.',
    schema: {
      example: {
        statusCode: 200,
        status: 'success',
        message: 'All users fetched successfully.',
        data: [
          {
            id: 2,
            firstName: 'Aritra',
            lastName: 'Bera',
            email: 'aritrabera54@gmail.com',
            phoneNumber: '1234567890',
            verifiedUser: true,
            createdAt: '2025-01-01T19:21:42.324Z',
            updatedAt: '2025-01-01T19:23:02.472Z'
          },
          {
            id: 3,
            firstName: 'Robo',
            lastName: 'Droid',
            email: 'robodroid@gmail.com',
            phoneNumber: '1234567890',
            verifiedUser: false,
            createdAt: '2025-01-01T21:06:55.142Z',
            updatedAt: '2025-01-01T21:07:55.596Z'
          },
          {
            id: 1,
            firstName: 'Aritra',
            lastName: 'Bera',
            email: 'aritrabera32@gmail.com',
            phoneNumber: '1234567890',
            verifiedUser: true,
            createdAt: '2025-01-01T19:19:26.392Z',
            updatedAt: '2025-01-01T21:33:14.693Z'
          }
        ]
      }
    }
  })
  @ApiInternalServerErrorResponse({
    description: 'An unexpected error occurred while fetching the list of users.',
    schema: {
      example: {
        statusCode: 500,
        status: 'error',
        message: 'Internal Server Error.'
      }
    }
  })
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
