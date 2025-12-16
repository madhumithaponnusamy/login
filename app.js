require('dotenv').config();
const express = require('express');
const app = express();
const PORT = 3009;
const path = require('path');

const rfs = require('rotating-file-stream');
const pino = require('pino');
const pinoHttp = require('pino-http');
const session = require('express-session');
const MySQLStore = require("express-mysql-session")(session);

const db = require('./db/db');   
const crypto = require("crypto");
const { saveLog } = require("./logger/logger");

app.use(express.static("public"));
app.use("/upload", express.static(path.join(__dirname, "upload")));


const generator = (time) => {
    const d = time || new Date();
    return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}.log`;
};

const stream = rfs.createStream(generator, {
    interval: '1d',
    path: path.join(__dirname, 'logs'),
});

const logger = pino(
    { transport: { target: "pino-pretty", options: { colorize: true } } },
    stream
);


app.use(pinoHttp({ logger }));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

const sessionStore = new MySQLStore({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    checkExpirationInterval: 900000,
    expiration: 1000 * 60 * 60 * 2
});


app.use(session({
    name: 'madhu',
    secret: process.env.SESSION_SECRET || 'change_this_secret',
    store: sessionStore,
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, 
        secure: false, 
        maxAge: 1000 * 60 * 60 * 2 }
}));


app.use((req, res, next) => {
    req.reqId = crypto.randomBytes(8).toString("hex");
    next();
});


app.use((req, res, next) => {
    req.db = db;
    next();
});


app.use((req, res, next) => {
    const start = Date.now();
    res.on("finish", () => {
        saveLog(req.db, {
            reqId: req.reqId,
            level: "request",
            msg: "HTTP Request",
            meta: {
                method: req.method,
                url: req.url,
                status: res.statusCode,
                responseTime: Date.now() - start + "ms"
            }
        });
    });
    next();
});


app.set("view engine", "ejs");
app.set("views", [path.join(__dirname, "views")]);



const signUpcontroller = require("./controller/signup.controller");
signUpcontroller.setUpRoutes(app);



app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
