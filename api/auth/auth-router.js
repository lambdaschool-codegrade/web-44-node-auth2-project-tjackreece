const bcryptjs = require("bcryptjs");
const jwt = require("jsonwebtoken");
const router = require("express").Router();

const Users = require("../users/users-model");
const { checkUsernameExists, validateRoleName } = require("./auth-middleware");
const { JWT_SECRET } = require("../secrets"); // use this secret!

router.post("/register", validateRoleName, (req, res, next) => {
	/**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }
    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
	const { username, password } = req.body;

	if (!username || !password) {
		res.status(400).json({
			message: "Please provide a username and password",
		});
	} else {
		const hash = bcryptjs.hashSync(password, 10);

		Users.add({ ...req.body, password: hash })
			.then((user) => {
				res.status(201).json(user);
			})
			.catch((err) => {
				res.status(500).json({ message: err.message });
			});
	}
});

router.post("/login", checkUsernameExists, (req, res, next) => {
	/**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }
    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }
    The token must expire in one day, and must provide the following information
    in its payload:
    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */
	const { username, password } = req.body;

	if (!username || !password) {
		res.status(400).json({
			message: "Please provide a username and password",
		});
	} else {
		const user = req.user;

		if (bcryptjs.compareSync(password, user.password)) {
			const token = makeToken(user);
			res.status(200).json({ message: `${user.username} is back`, token });
		} else {
			res.status(401).json({ message: "Invalid credentials" });
		}
	}
});

function makeToken(user) {
	const payload = {
		subject: user.user_id,
		username: user.username,
		role_name: user.role_name,
	};
	const options = {
		expiresIn: "30 seconds",
	};
	return jwt.sign(payload, JWT_SECRET, options);
}

module.exports = router;
