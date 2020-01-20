import { Module } from '@nestjs/common';
import { AuthController } from './auth/auth.controller';
import { AuthModule } from './auth/auth.module';

@Module({
  imports: [AuthModule],
  controllers: [],
  providers: [],
})
export class AppModule {}
