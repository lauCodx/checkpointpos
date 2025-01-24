import { NextFunction, Request, Response } from "express";
import { URequest, User } from "../interfaces/user.signin.interface";
import { UserService } from "../services/user.service";
import { error } from "console";


export class UserController {
    constructor(private userService: UserService){}

    async signUp(req: Request, res: Response, next: NextFunction): Promise<void> {
        const user: User = req.body
        const { email, password } = user;
        try {
            if (!email || !password){
                throw new Error('Email and password are required')
            }

            const newUser = await this.userService.create({email, password});
            res.status(201).json({
                message: 'User created successfully',
                data: newUser
            });
        } catch (error) {
            next(error)
        }
    }

    async signIn(req: Request, res: Response, next: NextFunction): Promise<void> {
        const user = req.body;
        try {
            if (!user.email || !user.password){
                throw new Error('Email and password are required')
            }
            const token = await this.userService.signIn(user);
            res.status(200).json({
                message: 'User signed in successfully',
                data: token
            });
        } catch (error) {
            next(error)
        }
    }

    async protectedRoute(req: URequest, res: Response, next: NextFunction): Promise<void> {
        const user = req.user;
        res.status(200).json({
            message: 'Protected route',
            data: user
        });
    }

}