const express = require("express");
const User = require("../models/user");
const { ensureLoggedIn } = require("../middleware/auth");

const router = new express.Router();

/** GET / - get list of users.
 *
 * => {users: [{username, first_name, last_name, phone}, ...]}
 *
 **/

router.get("/", ensureLoggedIn, async (req, res, next) => {
    try {
        const users = await User.all();
        return res.json({ users });
    } catch (error) {
        return next(error);
    }
});

/** GET /:username - get detail of users.
 *
 * => {user: {username, first_name, last_name, phone, join_at, last_login_at}}
 *
 **/

router.get("/:username", ensureLoggedIn, async (req, res, next) => {
    try {
        let user = await User.get(req.params.username);
        return res.json({user});
    } catch (error) {
        next(error);
    }
});

/** GET /:username/to - get messages to user
 *
 * => {messages: [{id,
 *                 body,
 *                 sent_at,
 *                 read_at,
 *                 from_user: {username, first_name, last_name, phone}}, ...]}
 *
 **/

router.get("/:username/to", ensureLoggedIn, async (req, res, next) => {
    try {
        let messages = await User.messagesTo(req.params.username);
        return res.json({messages});
    } catch (error) {
        next(error);
    }
});

/** GET /:username/from - get messages from user
 *
 * => {messages: [{id,
 *                 body,
 *                 sent_at,
 *                 read_at,
 *                 to_user: {username, first_name, last_name, phone}}, ...]}
 *
 **/

router.get("/:username/from", ensureLoggedIn, async (req, res, next) => {
    try {
        let messages = await User.messagesFrom(req.params.username);
        return res.json({messages});
    } catch (error) {
        next(error);
    }
});

module.exports = router;