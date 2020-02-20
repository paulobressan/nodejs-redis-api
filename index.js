const express = require("express");
const redis = require("redis");
const joi = require("joi");
const { BAD_REQUEST, OK } = require("http-status");
const bcrypt = require("bcrypt");
const { promisify } = require("util");
const jsonwebtoken = require("jsonwebtoken");

const userSchema = joi.object({
  name: joi.string().required(),
  login: joi.string().required(),
  password: joi.string().required()
});

const app = express();
const client = redis.createClient({
  host: "127.0.0.1",
  port: 6379,
  db: 0
});

app.use(express.json());

app.post("/users", async (req, res, next) => {
  try {
    const user = req.body;
    const { error } = userSchema.validate(user);
    if (error) {
      res.status(BAD_REQUEST).json({
        code: BAD_REQUEST,
        message: error.message
      });
      return next();
    }

    const getAsync = promisify(client.get).bind(client);
    const hasUser = await getAsync(user.login);
    if (hasUser) {
      res.status(BAD_REQUEST).json({
        code: BAD_REQUEST,
        message: "Invalid login."
      });
      return next();
    }

    user.password = await bcrypt.hash(user.password, 10);
    client.SET(user.login, JSON.stringify(user));
    delete user.password;
    res.status(OK).json(user);
  } catch (err) {
    res.json(err);
  }
});

app.post("/users/authenticate", async (req, res, next) => {
  try {
    const auth = req.body;
    const getAsync = promisify(client.get).bind(client);
    const user = await getAsync(auth.login);
    if (!user) {
      res.status(BAD_REQUEST).json({
        code: BAD_REQUEST,
        message: "Invalid login."
      });
      return next();
    }

    const userJSON = JSON.parse(user);

    if (!(await bcrypt.compare(auth.password, userJSON.password))) {
      res.status(BAD_REQUEST).json({
        code: BAD_REQUEST,
        message: "Invalid password."
      });
      return next();
    }

    const token = jsonwebtoken.sign(
      {
        user: userJSON.login
      },
      "nodejs_redis_api",
      {
        expiresIn: "1h",
        subject: userJSON.login,
        issuer: "nodejsapi"
      }
    );

    res.status(OK).json({ token });
  } catch (err) {
    res.json(err);
  }
});

app.listen(5000, () => console.info("Server run"));
