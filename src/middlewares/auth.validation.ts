import { NextFunction, Request, Response } from "express";
import jwt from 'jsonwebtoken';
import { URequest } from "../interfaces/user.signin.interface";

export const validateToken = async (req: URequest, res: Response, next: NextFunction) => {
    const authHeader = req.headers ['authorization'];
    try {
        if(!authHeader && !authHeader?.startsWith('Bearer ')){
            throw new Error('No token provided');
        }
        const token = authHeader.split(' ')[1];
        const decoded: any = jwt.verify(token, process.env.JWT_SECRET as string);
        if(!decoded){
            throw new Error('Unauthorized');
        }
        req.user = decoded;
        next();

        
    } catch (error) {
        next(error)
    }
}