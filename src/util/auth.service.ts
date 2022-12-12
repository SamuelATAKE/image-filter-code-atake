import { NextFunction, Request, Response } from "express";

import * as jwt from "jsonwebtoken";
import { config } from './config';

export function requireAuth(req: Request, res: Response, next: NextFunction) {
    if (!req.headers || !req.headers.authorization) {
        return res.status(401).send({ message: 'No authorization headers found.' });
    }

    const bearerToken = req.headers.authorization.split(' ');

    if (bearerToken.length != 2) {
        return res.status(401).send({ message: 'Your token is malformed.' });
    }

    return jwt.verify(bearerToken[1], config.jwt.secret, (error: any) => {
        if (error) {
            return res.status(500).send({ auth: false, message: 'Failed to authenticate!' });
        }
        return next();
    });
}