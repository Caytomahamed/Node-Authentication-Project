const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const router = require("express").Router();
const { validateRoleName, checkUsernameExists } = require("./auth-middleware");
// require JWT_SECRET from .env file // use this secret!
const users = require("../users/users-model.js");

router.post("/register", validateRoleName, async (req, res, next) => {
  try {
    const { username, password, role_name } = req.body;
    const hash = bcrypt.hashSync(password, 10);

    const u = await users.add({ username, password: hash, role_name });

    res.status(201).json({ message: `you are now registered, ${username}` });
  } catch (error) {
    res.status(500).json({ message: `Error registering user ${error}` });
    console.log(error);
    next(error);
  }
});

const generateToken = (user) => {
  const payload = {
    subject: user.user_id,
    username: user.username,
    role_name: user.role_name,
  };

  const options = {
    expiresIn: "24h",
  };

  return jwt.sign(payload, process.env.JWT_SECRET, options);
};

router.post("/login", checkUsernameExists, async (req, res, next) => {
  try {
    const { username, password } = req.body;

    const [existUser] = await users.findBy({ username });

    if (!bcrypt.compareSync(password, existUser.password)) {
      res.status(401).json({ message: "Invalid credentials" });
      return;
    }

    req.session.user = existUser;

    const token = generateToken(existUser);

    res.status(200).json({ message: `${username} is back!`, token });
  } catch (error) {
    console.log(error);
    next(error);
  }
});

router.get("/logout", (req, res, next) => {
  if (req.session.user == null) {
    res.status(400).json({ message: "You are not logged in" });
    return;
  }

  const username = req.session.user.username;

  req.session.destroy((erro) => {
    if (erro) {
      res.status(500).json({ message: "Error logging out" });
      return;
    }

    res.status(200).json({ message: `${username} has been logged out` });
  });
});

module.exports = router;

//

//

// TODO:

// NOTE: register
/**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "team lead" }
 
    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "team lead"
    } 
   */

// NOTE: login
/**
    [POST] /api/auth/login { "username": "Hamdi", "password": "1234" }

    response:
    status 200
    {
      "message": "Hamdi is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "hamdi"   // the username of the authenticated user
      "role_name": "instructor" // the role of the authenticated user
    }
   */

// NOTE: login out
/**
 * [GET] /api/auth/logout
 * response:
 * status 200
 * {
 *  "message": "You have been logged out"
 * }
 */
