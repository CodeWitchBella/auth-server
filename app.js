const express = require('express');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const cookieParser = require('cookie-parser');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');

const usersString = fs.readFileSync(path.join(__dirname, 'users.txt'), 'utf-8')
let changed = false
const users = new Map(usersString.split('\n').filter(line => line.includes(':') && !line.startsWith('#')).map(line => {
  let [name, password] = line.split(':').map(v => v.trim())
  if (!password.startsWith('$')) {
    password = bcrypt.hashSync(password);
    changed = true
  }
  return [ name, password ]
}))
if (changed) {
  fs.writeFileSync(
    path.join(__dirname, 'users.txt'),
    Array.from(users.entries()).map(u => u.join(':')).join('\n') + '\n',
    'utf-8'
  )
}

const app = express();

// rate limiter used on auth attempts
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 15,
  message: {
    status: 'fail',
    message: 'Too many requests, please try again later',
  },
});

// read .env and store in process.env
dotenv.config();

// config vars
const port = process.env.AUTH_PORT || 3003;
const tokenSecret = process.env.AUTH_TOKEN_SECRET;
const defaultUser = 'user'; // default user when no username supplied
const expiryDays = 7;

if (!tokenSecret) {
  console.error(
    'Misconfigured server. Environment variables AUTH_PASSWORD and/or AUTH_TOKEN_SECRET are not configured'
  );
  process.exit(1);
}

// middleware to check auth status
const jwtVerify = (req, res, next) => {
  // get token from cookies
  const token = req.cookies.authToken;

  // check for missing token
  if (!token) return next();

  jwt.verify(token, tokenSecret, (err, decoded) => {
    if (err) {
      // e.g malformed token, bad signature etc - clear the cookie also
      console.log(err);
      res.clearCookie('authToken');
      return res.status(403).send(err);
    }

    req.user = decoded.user || null;
    next();
  });
};

// using single password for the time being, but this could query a database etc
const checkAuth = (user, pass) => {
  const hash = users.get(user)
  if (hash && bcrypt.compareSync(pass, hash)) return true;
  return false;
};

app.set('view engine', 'ejs');

// logging
app.use(morgan('dev'));

// serve static files in ./public
app.use(express.static('public'));

// parse cookies
app.use(cookieParser());

// parse json body
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// check for JWT cookie from requestor
// if there is a valid JWT, req.user is assigned
app.use(jwtVerify);

// interface for users who are logged in
app.get('/__auth/logged-in', (req, res) => {
  if (!req.user) return res.redirect('/login');
  return res.render('logged-in', { user: req.user || null });
});

// login interface
app.get('/__auth/login', (req, res) => {
  // parameters from original client request
  // these could be used for validating request
  const requestUri = req.headers['x-original-uri'];
  const remoteAddr = req.headers['x-original-remote-addr'];
  const host = req.headers['x-original-host'];

  // check if user is already logged in
  if (req.user) return res.redirect('/__auth/logged-in');

  // user not logged in, show login interface
  return res.render('login', {
    referer: requestUri ? `${host}/${requestUri}` : '/',
    fail: req.query.status === 'fail',
  });
});

// endpoint called by NGINX sub request
// expect JWT in cookie 'authToken'
app.get('/__auth/auth', (req, res, next) => {
  // parameters from original client request
  // these could be used for validating request
  const requestUri = req.headers['x-original-uri'];
  const remoteAddr = req.headers['x-original-remote-addr'];
  const host = req.headers['x-original-host'];

  if (req.user) {
    // user is already authenticated, refresh cookie

    // generate JWT
    const token = jwt.sign({ user: req.user }, tokenSecret, {
      expiresIn: `${expiryDays}d`,
    });

    // set JWT as cookie, 7 day age
    res.cookie('authToken', token, {
      httpOnly: true,
      maxAge: 1000 * 86400 * expiryDays, // milliseconds
      secure: true,
    });

    return res.sendStatus(200);
  } else {
    // not authenticated
    return res.sendStatus(401);
  }
});

// endpoint called by login page, username and password posted as JSON body
app.post('/__auth/login', apiLimiter, (req, res) => {
  const { username, password } = req.body;
  const form = req.get('content-type') === 'application/x-www-form-urlencoded'

  if (checkAuth(username, password)) {
    // successful auth
    const user = username || defaultUser;

    // generate JWT
    const token = jwt.sign({ user }, tokenSecret, {
      expiresIn: `${expiryDays}d`,
    });

    // set JWT as cookie, 7 day age
    res.cookie('authToken', token, {
      httpOnly: true,
      maxAge: 1000 * 86400 * expiryDays, // milliseconds
      secure: true,
    });
    if (form) {
      return res.redirect('/__auth/login')
    }
    return res.send({ status: 'ok' });
  }

  if (form) {
    return res.redirect('/__auth/login?status=fail')
  }

  // failed auth
  res.status(401).send({ status: 'fail', message: 'Invalid credentials' });
});

// force logout
app.get('/__auth/logout', (req, res) => {
  res.clearCookie('authToken');
  res.redirect('/login');
});

// endpoint called by logout page
app.post('/__auth/logout', (req, res) => {
  res.clearCookie('authToken');
  res.sendStatus(200);
});

// default 404
app.use((req, res, next) => {
  res.redirect('/__auth/login', 307);
});

app.listen(port, () => console.log(`Listening at http://localhost:${port}`));
