import express from 'express'
import { UserService } from '../services/user.service';
import { UserController } from '../controllers/user.controller';
import { validateToken } from '../middlewares/auth.validation';

const router = express.Router();

const userService = new UserService()
const userController = new UserController(userService)

router.post('/signup', userController.signUp.bind(userController));
router.post('/signin', userController.signIn.bind(userController));
router.get('/protected',validateToken, userController.protectedRoute.bind(userController));


export default router