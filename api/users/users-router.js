const router = require("express").Router();
const Users = require("./users-model.js");
const { restricted, checkRoleType } = require("../auth/auth-middleware.js");

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
router.get("/", restricted,(req, res, next) => { 
  console.log("req.session.user", req.session.user);
  if(req.session.user == null){
    res.status(430).json({ message: "You are not logged in" });
    return;
  }
  // done for you
  Users.find()
    .then(users => {
      res.json(users);
    })
    .catch(next);
});

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
router.get("/:user_id", restricted, checkRoleType,(req, res, next) => { 
  // done for you
  Users.findById(req.params.user_id)
    .then(user => {
      res.json(user);
    })
    .catch(next);
});

module.exports = router;
