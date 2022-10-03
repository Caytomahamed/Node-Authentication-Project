require("dotenv").config();
const session = require("express-session");
const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const authRouter = require("./auth/auth-router.js");
const usersRouter = require("./users/users-router.js");

/**
  Do what needs to be done to support sessions with the `express-session` package!
  To respect users' privacy, do NOT send them a cookie unless they log in.
  This is achieved by setting 'saveUninitialized' to false, and by not
  changing the `req.session` object unless the user authenticates.

  Users that do authenticate should have a session persisted on the server,
  and a cookie set on the client. The name of the cookie should be "chocolatechip".
 */

const server = express();

const sessionConfig = {
  name: "assigment",
  secret: process.env.JWT_SECRET,
  saveUninitialized: false, 
  resave: false,
  cookie: {
    maxAge: 1000 * 60 * 60 * 24,
    httpOnly: true,
    secret: false,
  },
};

server.use(session(sessionConfig));

server.use(helmet());
server.use(express.json());
server.use(cors()); 

server.use("/api/auth", authRouter);
server.use("/api/users", usersRouter); 
  
module.exports = server;
