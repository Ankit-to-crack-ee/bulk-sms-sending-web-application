const express = require('express');
const app = express();
const path = require('path');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const session = require('express-session');
const User = require('./models/User');
const PORT = process.env.PORT || 3000;
const jwtSecret = process.env.JWT_SECRET || 'your_jwt_secret';

mongoose.set('strictQuery', true);
mongoose.connect('mongodb://127.0.0.1:27017/carpooling', {
  useUnifiedTopology: true,
})
  .then(() => { console.log("DB CONNECTED"); })
  .catch((err) => { console.log("Error in DB", err); });

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(session({
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: true,
  cookie: {
    secure: false,
    maxAge: 3600000,
  }
}));

const authenticateJWT = (req, res, next) => {
  const token = req.session.token || req.cookies.token; // Check both session and cookies
  if (token) {
    jwt.verify(token, jwtSecret, (err, decoded) => {
      if (err) {
        return res.status(403).send('Unauthorized');
      }
      req.user = decoded; // Attach user data to req object
      next();
    });
  } else {
    res.status(401).send('Unauthorized');
  }
};

app.post('/signup', async (req, res) => {
  const { username, password } = req.body;
  try {
    let user = await User.findOne({ username });
    if (user) {
      return res.status(400).send('Username already exists');
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    user = new User({
      username,
      password: hashedPassword
    });

    await user.save();
    res.redirect('/login');
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).send('Invalid username or password');
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).send('Invalid username or password');
    }

    const token = jwt.sign({ id: user._id, username: user.username }, jwtSecret, { expiresIn: '1h' });
    req.session.token = token;
    res.cookie('token', token, { maxAge: 3600000, httpOnly: true });

    res.redirect('/');
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});

app.get('/', authenticateJWT, async (req, res) => {
  res.render('emailservice', { user: req.user });
});

app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).send('Logout failed');
    }
    res.clearCookie('token');
    res.redirect('/login');
  });
});

app.get('/signup', (req, res) => {
  res.render('signup');
});

app.get('/login', (req, res) => {
  res.render('login');
});

app.listen(PORT, () => console.log(`Server started on port ${PORT}`));


// ___________________________________________________________________________________

ACCOUNT_SID = 'AC61226639acace4cd66a4f45b30c239f8'
AUTH_TOKEN = 'd9a0e5e78340030d6432dbfd35c042da'
TWILIO_PHONE_NUMBER = '+12679334036'
const client = require('twilio')(ACCOUNT_SID, AUTH_TOKEN); 
const twilio = require('twilio');
const TwilioClient = twilio(ACCOUNT_SID,AUTH_TOKEN);

app.get('/bulk-messages', authenticateJWT, (req, res) => {
    res.render('bulkMessages',{ user: req.user });
});

app.post('/send-bulk-messages', authenticateJWT, async (req, res) => {
    const { phoneNumbers, message } = req.body;
    const numbers = phoneNumbers.split(',').map(num => num.trim());
    
    try {
        const promises = numbers.map(number => {
            return TwilioClient.messages.create({
                body: message,
                from: TWILIO_PHONE_NUMBER, // Your Twilio phone number
                to: number
            });
        });

        await Promise.all(promises);
        res.send('Bulk messages sent successfully.');
    } catch (error) {
        console.error(error);
        res.status(500).send('Failed to send bulk messages.');
    }
});

