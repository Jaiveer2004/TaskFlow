require('dotenv').config();
const express = require('express');
const { MongoClient } = require('mongodb');
const path = require('path');
const bcrypt = require('bcrypt');
const session = require('express-session');
const MongoDBStore = require('connect-mongodb-session')(session);
const bodyParser = require('body-parser');
const { body, validationResult } = require('express-validator');
const rateLimit = require('express-rate-limit');
const compression = require('compression');
const cache = require('memory-cache');

const app = express();
const PORT = process.env.PORT || 8081;

// Validate environment variables
if (!process.env.MONGODB_URI) {
  throw new Error('MONGODB_URI is not defined in .env');
}
if (!process.env.SESSION_SECRET) {
  throw new Error('SESSION_SECRET is not defined in .env');
}

// MongoDB connection
const client = new MongoClient(process.env.MONGODB_URI, { 
  useUnifiedTopology: true, 
  maxPoolSize: 10, 
  minPoolSize: 2, 
  connectTimeoutMS: 10000, 
  serverSelectionTimeoutMS: 5000 
});
let db;

// Session store
const store = new MongoDBStore({
  uri: process.env.MONGODB_URI,
  databaseName: 'taskflow',
  collection: 'sessions'
});

// Cache settings (in milliseconds)
const CACHE_DURATION = 10 * 60 * 1000; // 10 minutes

// Rate limiting for login and signup
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10,
  message: 'Too many attempts, please try again after 15 minutes'
});

// Middlewares
app.use(compression());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public', {
  maxAge: '1d',
  etag: true
}));
app.set('view engine', 'ejs');

if (process.env.NODE_ENV === 'production') {
  app.set('view cache', true);
}

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: store,
  cookie: { 
    httpOnly: true, 
    secure: process.env.NODE_ENV === 'production', // Secure in production
    maxAge: 2 * 60 * 60 * 1000 // 2 hours
  }
}));

// Set up MongoDB database, collections, and indexes
async function setupMongo() {
  try {
    await client.connect();
    db = client.db('taskflow');

    // Ensure collections exist
    const collections = await db.listCollections().toArray();
    const collectionNames = collections.map(c => c.name);
    
    if (!collectionNames.includes('users')) {
      await db.createCollection('users');
    }
    if (!collectionNames.includes('tasks')) {
      await db.createCollection('tasks');
    }

    // Manage users.username index
    const usersIndexes = await db.collection('users').indexes();
    const usernameIndex = usersIndexes.find(index => index.name === 'username_1');
    if (usernameIndex && !usernameIndex.unique) {
      await db.collection('users').dropIndex('username_1');
    }
    if (!usernameIndex || !usernameIndex.unique) {
      await db.collection('users').createIndex({ username: 1 }, { unique: true });
    }

    // Create tasks index
    const tasksIndexes = await db.collection('tasks').indexes();
    const taskIndex = tasksIndexes.find(index => index.name === 'userId_1_id_1');
    if (!taskIndex) {
      await db.collection('tasks').createIndex({ userId: 1, id: 1 });
    }
  } catch (err) {
    throw new Error('MongoDB setup failed: ' + err.message);
  }
}

// Helper functions with caching
async function getUsers(username = null) {
  const cacheKey = username ? `users_${username}` : 'users';
  const cachedUsers = cache.get(cacheKey);
  if (cachedUsers) {
    return cachedUsers;
  }
  try {
    let users;
    if (username) {
      users = await db.collection('users').find({ username }).toArray();
    } else {
      users = await db.collection('users').find().toArray();
    }
    cache.put(cacheKey, users, CACHE_DURATION);
    return users;
  } catch (err) {
    return [];
  }
}

async function saveUser(user) {
  try {
    await db.collection('users').insertOne(user);
    cache.del('users');
    cache.del(`users_${user.username}`);
  } catch (err) {
    throw err;
  }
}

async function getTasks(userId = null) {
  const cacheKey = userId ? `tasks_${userId}` : 'tasks';
  const cachedTasks = cache.get(cacheKey);
  if (cachedTasks) {
    return cachedTasks;
  }
  try {
    let tasks;
    if (userId) {
      tasks = await db.collection('tasks').find({ userId }).toArray();
    } else {
      tasks = await db.collection('tasks').find().toArray();
    }
    cache.put(cacheKey, tasks, CACHE_DURATION);
    return tasks;
  } catch (err) {
    return [];
  }
}

async function saveTask(task) {
  try {
    await db.collection('tasks').insertOne(task);
    cache.del('tasks');
    cache.del(`tasks_${task.userId}`);
  } catch (err) {
    throw err;
  }
}

async function updateTask(taskId, userId, updates) {
  try {
    await db.collection('tasks').updateOne(
      { id: taskId, userId },
      { $set: updates }
    );
    cache.del('tasks');
    cache.del(`tasks_${userId}`);
  } catch (err) {
    throw err;
  }
}

async function deleteTask(taskId, userId) {
  try {
    await db.collection('tasks').deleteOne({ id: taskId, userId });
    cache.del('tasks');
    cache.del(`tasks_${userId}`);
  } catch (err) {
    throw err;
  }
}

function isLoggedIn(req, res, next) {
  if (req.session.userId) {
    return next();
  }
  res.redirect('/login');
}

// Validation middleware
const signupValidation = [
  body('username')
    .trim()
    .isLength({ min: 3, max: 20 })
    .withMessage('Username must be 3-20 characters long')
    .isAlphanumeric()
    .withMessage('Username must contain only letters and numbers'),
  body('password')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters long')
    .matches(/[A-Z]/)
    .withMessage('Password must contain at least one uppercase letter')
    .matches(/[a-z]/)
    .withMessage('Password must contain at least one lowercase letter')
    .matches(/[0-9]/)
    .withMessage('Password must contain at least one number')
    .matches(/[!@#$%^&*(),.?":{}|<>]/)
    .withMessage('Password must contain at least one special character'),
  body('confirmPassword')
    .custom((value, { req }) => value === req.body.password)
    .withMessage('Passwords do not match')
];

const loginValidation = [
  body('username')
    .trim()
    .notEmpty()
    .withMessage('Username is required'),
  body('password')
    .notEmpty()
    .withMessage('Password is required')
];

const taskValidation = [
  body('title')
    .trim()
    .isLength({ min: 1, max: 100 })
    .withMessage('Title must be 1-100 characters long'),
  body('description')
    .trim()
    .isLength({ min: 1, max: 500 })
    .withMessage('Description must be 1-500 characters long'),
  body('category')
    .isIn(['Work', 'Personal', 'Urgent'])
    .withMessage('Invalid category'),
  body('status')
    .isIn(['Pending', 'In Progress', 'Completed'])
    .withMessage('Invalid status'),
  body('deadline')
    .isDate()
    .withMessage('Invalid date format')
    .custom((value) => {
      const today = new Date();
      today.setHours(0, 0, 0, 0);
      const inputDate = new Date(value);
      if (inputDate < today) {
        throw new Error('Deadline cannot be in the past');
      }
      return true;
    }),
  body('priority')
    .isIn(['Low', 'Medium', 'High'])
    .withMessage('Invalid priority'),
  body('latitude')
    .optional({ checkFalsy: true })
    .isFloat({ min: -90, max: 90 })
    .withMessage('Latitude must be between -90 and 90'),
  body('longitude')
    .optional({ checkFalsy: true })
    .isFloat({ min: -180, max: 180 })
    .withMessage('Longitude must be between -180 and 180')
];

// Routes
app.get('/signup', (req, res) => {
  res.render('signup', { error: null, errors: [] });
});

app.post('/signup', authLimiter, signupValidation, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.render('signup', { error: null, errors: errors.array() });
  }

  try {
    const { username, password } = req.body;
    const users = await getUsers(username);
    if (users.length > 0) {
      return res.render('signup', { error: 'Username already taken', errors: [] });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = { id: Date.now(), username, password: hashedPassword };
    await saveUser(user);

    req.session.userId = user.id;
    res.redirect('/login');
  } catch (err) {
    if (err.code === 11000) {
      return res.render('signup', { error: 'Username already taken', errors: [] });
    }
    res.render('signup', { error: 'Server error', errors: [] });
  }
});

app.get('/login', (req, res) => {
  res.render('login', { error: null, errors: [] });
});

app.post('/login', authLimiter, loginValidation, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.render('login', { error: null, errors: errors.array() });
  }

  try {
    const { username, password } = req.body;
    const users = await getUsers(username);
    const user = users[0];

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.render('login', { error: 'Invalid username or password', errors: [] });
    }

    req.session.userId = user.id;
    res.redirect('/');
  } catch (err) {
    res.render('login', { error: 'Server error', errors: [] });
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    res.redirect('/login');
  });
});

app.get('/', isLoggedIn, async (req, res) => {
  try {
    const tasks = await getTasks(req.session.userId);
    const users = await getUsers();
    const currentUser = users.find(u => u.id === req.session.userId);
    if (!currentUser) throw new Error('User not found');
    res.render('index', { tasks, currentUser });
  } catch (err) {
    res.redirect('/login');
  }
});

app.get('/add-task', isLoggedIn, (req, res) => {
  res.render('add-task', { errors: [] });
});

app.post('/add-task', isLoggedIn, taskValidation, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.render('add-task', { errors: errors.array() });
  }

  try {
    const { title, description, category, status, deadline, priority, latitude, longitude } = req.body;
    const task = {
      id: Date.now(),
      title,
      description,
      category,
      status,
      deadline,
      priority,
      userId: req.session.userId,
      latitude: latitude ? parseFloat(latitude) : null,
      longitude: longitude ? parseFloat(longitude) : null
    };
    await saveTask(task);
    res.redirect('/');
  } catch (err) {
    res.status(500).render('500', { title: 'Server Error' });
  }
});

app.get('/edit-task/:id', isLoggedIn, async (req, res) => {
  try {
    const taskId = parseInt(req.params.id);
    const task = (await getTasks(req.session.userId)).find(t => t.id === taskId && t.userId === req.session.userId);
    if (!task) throw new Error('Task not found');
    res.render('edit-task', { task, errors: [] });
  } catch (err) {
    res.status(404).render('404', { title: 'Page Not Found' });
  }
});

app.post('/edit-task/:id', isLoggedIn, taskValidation, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    const taskId = parseInt(req.params.id);
    const task = (await getTasks(req.session.userId)).find(t => t.id === taskId && t.userId === req.session.userId);
    return res.render('edit-task', { task, errors: errors.array() });
  }

  try {
    const taskId = parseInt(req.params.id);
    const updates = {
      title: req.body.title,
      description: req.body.description,
      category: req.body.category,
      status: req.body.status,
      deadline: req.body.deadline,
      priority: req.body.priority
    };
    await updateTask(taskId, req.session.userId, updates);
    res.redirect('/');
  } catch (err) {
    res.status(500).render('500', { title: 'Server Error' });
  }
});

app.get('/delete-task/:id', isLoggedIn, async (req, res) => {
  try {
    const taskId = parseInt(req.params.id);
    await deleteTask(taskId, req.session.userId);
    res.redirect('/');
  } catch (err) {
    res.status(500).render('500', { title: 'Server Error' });
  }
});

app.use((req, res) => {
  res.status(404).render('404', { title: 'Page Not Found' });
});

app.use((err, req, res, next) => {
  res.status(500).render('500', { title: 'Server Error' });
});

// Start server after MongoDB setup
setupMongo().then(() => {
  app.listen(PORT, () => {});
}).catch(err => {
  process.exit(1);
});