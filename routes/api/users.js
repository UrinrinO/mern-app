const express = require('express');
const router = express.Router();
const gravatar = require('gravatar');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('config');
const {
    body,
    validationResult
} = require('express-validator');

// Models
const User = require('../../models/User');

// @route POST api/users
// @desc Register user
// @access Public
router.post(
    '/',
    [
        body('name', "Name is required").not().isEmpty(),
        // email must be a valid email
        body('email', "Kindly enter a valid email address").isEmail(),
        // password must be at least 6 chars long
        body('password', "Password must be at least 6 characters long").isLength({
            min: 6
        })
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
            name,
            email,
            password
        } = req.body;

        try {
            // Check if User exists
            let user = await User.findOne({
                email
            });

            if (user) {
                return res.status(400).json({
                    errors: [{
                        msg: 'User already exists'
                    }]
                });
            }

            // Get gravatar
            const avatar = gravatar.url(email, {
                s: '200',
                r: 'pg',
                d: 'mm'
            })

            user = new User({
                name,
                email,
                avatar,
                password
            })

            // Encrypt Password
            const salt = await bcrypt.genSalt(10);

            user.password = await bcrypt.hash(password, salt);

            await user.save();

            // Return Jsonwebtoken
            const payload = {
                user: {
                    id: user.id
                }
            }

            jwt.sign(payload, config.get('jwtSecret'), {
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