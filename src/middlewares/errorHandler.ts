import { NextFunction, Request, Response } from "express";
import constants from "../constants";

export const errorHandler = (
  err: Error,
  req: Request,
  res: Response,
  next: NextFunction
) => {
    
  const statusCode = res.statusCode ? res.statusCode : 500;

  switch (statusCode) {
    case constants.VALIDATION_ERROR:
      res.json({ title: "Validation error", message: err.message });
      break;

    case constants.UNAUTHORIZED:
      res.json({ title: "Unauthorize", message: err.message });
      break;

    case constants.FORBIDDEN:
      res.json({ title: "Forbidden", message: err.message });
      break;

    case constants.NOT_FOUND:
      res.json({ title: "Not found", message: err.message });
      break;

    case constants.UNPROCESSABLE_ENTITY:
      res.json({ title: "Cannot be proccessed", message: err.message });
      break;

    case constants.SERVER_ERROR:
      res.json({ title: "Server error", message: err.message });
      break;

    default:
        console.error(err.message);
        res.status(400).json({ title: "An error occurred", message: err.message });
        break;
  }
};

