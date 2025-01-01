import { Logger, ValidationPipe } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { setupSwagger } from './module/swgger-docs/swagger.config';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Set global prefix for all routes
  app.setGlobalPrefix('api'); // All routes will now be prefixed with '/api'

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
    }),
  );

  // Setup Swagger
  setupSwagger(app);

  const PORT = process.env.PORT ?? 3000;
  await app.listen(PORT);

  Logger.log(`Application is running on: http://localhost:${PORT}/api`);
  Logger.log(`Swagger documentation available at http://localhost:${PORT}/api-docs`);
}
bootstrap();
