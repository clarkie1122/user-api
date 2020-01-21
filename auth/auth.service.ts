import { Injectable, ConflictException, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { Repository } from 'typeorm';
import { JwtService } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm';
import * as bcrypt from 'bcrypt';

import { UserEntity } from './user.entity';
import { Error } from '../enum/error-code.enum';
import { AuthCredentialsDto } from './dto/auth-credentials.dto';
import { JwtPayload } from './jwt-payload.interface';

@Injectable()
export class AuthService {
    constructor(
        @InjectRepository(UserEntity) private readonly UserRepository: Repository<UserEntity>,
        private jwtService: JwtService
    ) { }

    async signUp(
        authCredentialsDto: AuthCredentialsDto
    ): Promise<void> {
        const { username, password } = authCredentialsDto;
        const salt = await bcrypt.genSalt();
        const user = new UserEntity();

        user.username = username;
        user.salt = salt;
        user.password = await this.hashPassword(password, salt);

        try {
            await user.save();
        } catch (error) {
            if (error.code === Error.Duplicate) {
                throw new ConflictException('Username already exists');
            }

            throw new InternalServerErrorException();
        }
    }

    async signIn(
        authCredentialsDto: AuthCredentialsDto
    ): Promise<{ accessToken: string }> {
        const { username, password } = authCredentialsDto;

        // find user based on username
        const user = await this.UserRepository.findOne({ username });

        if (!user) {
            throw new UnauthorizedException('Invalid credentials');
        }

        // with the password provided we need to compare that to the hashed password in the db, we do this by calling the method supplied in the User entity
        if (user) {
            if (await !user.validatePassword(password)) {
                throw new UnauthorizedException('Invalid credentials');
            }
        }

        const payload: JwtPayload = { username };
        const accessToken = await this.jwtService.sign(payload);

        return { accessToken };
    }

    private async hashPassword(
        password: string,
        salt: string
    ): Promise<string> {
        // the salt is a random string generated as well as the jwt
        return bcrypt.hash(password, salt);
    }
}
