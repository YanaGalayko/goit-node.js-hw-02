import {HttpError} from "../helpers/HttpError.js";
import { isEmptySchema } from "../schemas/contact-schema.js";

const isEmptyBody = async(req, res, next) => {
    const {error} = isEmptySchema.validate(req.body);
    if(error) {
        return next(HttpError(406, error.message));
    }
    next()
};

export default isEmptyBody

