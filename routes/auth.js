const express = require('express');
const User = require('../models/User');
const router = express.Router();
const { body, validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fetchuser = require('../middleware/fetchuser');
const JWT_SECRET = 'iamsksakib'; // Secret JWT.

// ROUTE 1: Create a user using: POST "/api/auth/createuser". No login required.
router.post('/createuser', [
    body('name', 'Enter a valid name').isLength({ min: 3 }),
    body('email', 'Enter a valid email').isEmail(),
    body('password', 'Password must be 6 characters').isLength({ min: 6 }),
], async (req, res) => {
    // If there is error, return bad request and the errors.
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    try {
        // Check whether the user with same email already exist.
        let user = await User.findOne({ email: req.body.email });
        if (user) {
            return res.status(400).json('Sorry, a user with this email already exist.')
        }

        const salt = await bcrypt.genSalt(10);
        const securePassword = await bcrypt.hash(req.body.password, salt);

        // Create a new user.
        user = await User.create({
            name: req.body.name,
            email: req.body.email,
            password: securePassword,
        });

        const data = {
            user: {
                id: user.id
            }
        }

        const authToken = jwt.sign(data, JWT_SECRET);
        res.json({ authToken });
    }

    catch (error) {
        console.error(error.message);
        res.status(500).send("Some error occured.")
    }
});

// ROUTE 2: Authenticate a user using: POST "/api/auth/login". Login required.
router.post('/login', [
    body('email', 'Enter a valid email').isEmail(),
    body('password', 'Password can not be empty.').exists(),
], async (req, res) => {
    // If there is error, return bad request and the errors.
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { email, password } = req.body;
    try {
        let user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ error: "Sorry, user doesn't exist." });
        }

        const passwordCompare = await bcrypt.compare(password, user.password);
        if (!passwordCompare) {
            return res.status(400).json({ error: "Sorry, user doesn't exist." });
        }

        const data = {
            user: {
                id: user.id
            }
        }

        const authToken = jwt.sign(data, JWT_SECRET);
        res.json({ authToken });
    }

    catch (error) {
        console.error(error.message);
        res.status(500).send("Some error occured.")
    }
});

// ROUTE 3: Authenticate a user using: POST "/api/auth/getuser". Login required.
router.post('/getuser', fetchuser, async (req, res) => {

    try {
        userId = req.user.id;
        const user = await User.findById(userId).select("-password");
        res.send(user);
    } catch (error) {
        console.error(error.message);
        res.status(500).send("Some error occured.")
    }
});













module.exports = router;