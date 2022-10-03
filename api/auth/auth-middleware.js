// require JWT_SECRET from .env file // use this secret!
require("dotenv").config();
// require DB to get the user information
const users = require("../users/users-model.js");

const jwt = require("jsonwebtoken");

const restricted = (req, res, next) => {
  // destructed token
  const token = req.headers.authorization;

  // verify token
  if (token) {
    jwt.verify(token, process.env.JWT_SECRET, async (error, decoded) => {
      if (error != null) {
        res.status(401).json({ message: `access restrict ${error}` });
        return;
      }
      const user = await users.findById(decoded.subject);

      if (user == null) {
        res.status(401).json({ message: "access restrict" });
        return;
      } else {
        req.decodedJwt = decoded;
        next();
      }
    });
  } else {
    res.status(400).json({ message: "no token, no access" });
  }
};

const checkRoleType = (role_name) => (req, res, next) => {
  try {
    const decoded = req.decodedJwt;
    if (decoded.role_name !== role_name) {
      res.status(403).json({ message: "This is not for you" });
      return;
    } else {
      req.decodedJwt = decoded;
      next();
    }
  } catch (error) {
    next(error);
  }
};

const checkUsernameExists = async (req, res, next) => {
  try {
    const { username } = req.body;
    const user = await users.findBy({ username }).first();

    if (!user) {
      res.status(401).json({ message: "Invalid credentials" });
      return;
    }

    next();
  } catch (error) {
    res.status(500).json({ message: "Error checking username" });
  }
};

const validateRoleName = (req, res, next) => {
  try {
    if (req.body.role_name) {
      req.body.role_name = req.body.role_name.trim();
    }
    if (req.body.role_name === "admin") {
      next({ status: 422, message: "Role name can not be admin" });
    }
    if (!req.body.role_name || req.body.role_name === "") {
      req.body.role_name = "student";
    }
    if (req.body.role_name.length > 32) {
      next({
        status: 422,
        message: "Role name can not be longer than 32 chars",
      });
    }
    next();
  } catch (error) {
    res.status(500).json({ message: `Error validating role name  , ${error}` });
  }
};

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  checkRoleType,
};

// TODO:

// NOTE: restricted
/*
    If the user does not provide a token in the Authorization header:
    status 401
    {
      "message": "Token required"
    }

    If the provided token does not verify:
    status 401
    {
      "message": "Token invalid"
    }

    Put the decoded token in the req object, to make life easier for middlewares downstream!
  */

// NOTE:checkRoleType
/*
    If the user does not provide a token in the Authorization header with a role_name
    inside its payload matching the role_name passed to this function as its argument:
    status 403
    {
      "message": "This is not for you"
    }

    Pull the decoded token from the req object, to avoid verifying it again!
  */

// NOTE: checkUsernameExists,
/*
    If the username in req.body does NOT exist in the database
    status 401
    {
      "message": "Invalid credentials"
    }
  */

// NOTE: validateRoleName
/*
    If the role_name in the body is valid, set req.role_name to be the trimmed string and proceed.

    If role_name is missing from req.body, or if after trimming it is just an empty string,
    set req.role_name to be 'student' and allow the request to proceed.

    If role_name is 'admin' after trimming the string:
    status 422
    {
      "message": "Role name can not be admin"
    }

    If role_name is over 32 characters after trimming the string:
    status 422
    {
      "message": "Role name can not be longer than 32 chars"
    }
  */
