const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const auth = require('../../middleware/auth');
const jwt = require('jsonwebtoken');
const config = require('config');
const {
    body,
    validationResult
} = require('express-validator');

const User = require('../../models/User');

// @route GET api/auth
// @desc Test route
// @access Public
router.get('/', auth, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        res.json(user);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Errors');
    }
});

// @route POST api/auth
// @desc Authenticate user & get token
// @access Public
router.post(
    '/',
    [
        // email must be a valid email
        body('email', 'Kindly enter a valid email address').isEmail(),
        // password must be at least 6 chars long
        body('password', 'Password is required').exists()
    ],
    async (req, res) => {
        // Finds the validation errors in this request and wraps them in an object with handy functions
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                errors: errors.array()
            });
        }

        const {
            email,
            password
        } = req.body;

        try {
            // Check if User exists
            let user = await User.findOne({
                email
            });

            if (!user) {
                return res.status(400).json({
                    errors: [{
                        msg: 'Invalid Credentials'
                    }]
                });
            }

            const isMatch = bcrypt.compare(password, user.password);

            if (!isMatch) {
                return res.status(400).json({
                    errors: [{
                        msg: 'Invalid Credentials'
                    }]
                });
            }

            // if (!await bcrypt.compare(password, user.password)) {
            //     return res.send({
            //         msg: 'Invalid credentials.'
            //     })
            // }

            // Return Jsonwebtoken
            const payload = {
                user: {
                    id: user.id
                }
            };

            jwt.sign(
                payload,
                config.get('jwtSecret'), {
                    expiresIn: 3600
                },
                (err, token) => {
                    if (err) {
                        throw err;
                    }
                    res.json({
                        token
                    });
                }
            );
        } catch (err) {
            console.error(err.message);
            res.status(500).send('Server Error');
        }
    }
);

module.exports = router;