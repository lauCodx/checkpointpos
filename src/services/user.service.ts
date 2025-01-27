import admin, { db } from "../config/db.config";
import { SigninUserInterface, User } from "../interfaces/user.signin.interface";
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken'

const Admin = admin.auth()

export class UserService {

    async create(user: User): Promise<User | any> {
        const email = user.email;
        const password = user.password;
        try {
            
            const existingUser = await Admin.getUserByEmail(email).catch(() => null);
            if (existingUser){
                throw new Error('User already exists');
            }
            const hashPassword = await bcrypt.hash(password, 10);
            const newUser = await Admin.createUser({
                ...user,
                password: hashPassword
            })
            await db.collection('Users').doc(newUser.uid).set({
                uid: newUser.uid,
                ...user
            })

            return newUser
            
        } catch (error) {
            throw error
        }
    };

    async signIn(user: SigninUserInterface): Promise<string> {
        const email = user.email;
        const password = user.password;
        try {
            const userExist = await db.collection('Users').doc(email.toLowerCase()).get();

            const userData = userExist.data();
            if (!userData) {
                throw new Error('User data does not exist');
            }
            const checkPassword = await bcrypt.compare(password, userData.password);
            if (!checkPassword){
                throw new Error('Invalid credentials')
            }
            
            const token = jwt.sign(
                {id: userData.id, email: userData.email, role: userData.role}, 
                process.env.JWT_SECRET as string, 
                {expiresIn: '1h'}
            );

            return token

        } catch (error) {
            throw error
        }
    }
}