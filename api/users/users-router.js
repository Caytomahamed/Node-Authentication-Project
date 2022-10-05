const router = require("express").Router();
const Users = require("./users-model.js");
const { restricted, checkRoleType } = require("../auth/auth-middleware.js");

router.get("/", restricted, (req, res) => {
  if (req.session.user == null) {
    res.status(430).json({ message: "You are not logged in" });
    return;
  }
  // done for you
  Users.find()
    .then((users) => {
      res.json(users);
    })
    .catch((erro) => console.log(erro));
});

router.get("/:user_id",restricted, checkRoleType('admin'), (req, res, next) => {
    if (req.session.user == null) {
      res.status(430).json({ message: "You are not logged in" });
      return;
    }
  // done for you
  console.log(req.body);
  Users.findById(req.params.user_id)
    .then((user) => {
      console.log(user);
      res.json(user);
    })
    .catch(next);
});

module.exports = router;

//  TODO: DOCUMANTATION

// NOTE: get all users
/**
  [GET] /api/users

  This endpoint is RESTRICTED: only authenticated clients
  should have access.

  response:
  status 200
  [
    {
      "user_id": 1,
      "username": "mohamed"
    }
  ]
 */

// NOTE: get by id
/**
  [GET] /api/users/:user_id

  This endpoint is RESTRICTED: only authenticated users with role 'admin'
  should have access.

  response:
  status 200
  [
    {
      "user_id": 1,
      "username": "mohamed"
    }
  ]
 */
