import { NextFunction, Request, Response } from "express";
import { URequest } from "../interfaces/user.signin.interface";
import admin from "../config/db.config";
const Admin = admin.auth();

export const validateToken = async (req: URequest, res: Response, next: NextFunction) => {
    const authHeader = req.headers ['authorization'];
    try {
        if(!authHeader && !authHeader?.startsWith('Bearer ')){
            throw new Error('No token provided');
        }
        const token = authHeader.split(' ')[1];
        const decoded: any = await Admin.verifyIdToken(token);
        if(!decoded){
            throw new Error('Unauthorized or token expired');
        }
        req.user = decoded;
        next();

        
    } catch (error) {
        next(error)
    }
}