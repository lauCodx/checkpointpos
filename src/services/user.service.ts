import { db } from "../config/db.config";
import { SigninUserInterface, User } from "../interfaces/user.signin.interface";
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken'

export class UserService {
    async findUserByEmail(email: string): Promise<User | null> {
        const userRef = db.collection('Users').doc(email.toLowerCase());
        const doc = await userRef.get();
        if (doc.exists) {
            throw new Error('User already exist');
        }
        return doc.data() as User;
    };

    async create(user: User): Promise<User> {
        const email = user.email;
        const password = user.password;
        try {
            const userRef = db.collection('Users').doc(email.toLowerCase())
            const userExist = await userRef.get();
            if (userExist.exists) {
                throw new Error('User already exists');
            };
            const hashPassword = await bcrypt.hash(password, 10);
            await userRef.set({...user, password:hashPassword});
            return user
            
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