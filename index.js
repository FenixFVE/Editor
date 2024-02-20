const { promisify } = require('util');
const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
const fs = require('fs');
const path = require('path');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const dotenvResult = require('dotenv').config();

const PORT = process.env.PORT || 3000;

const app = express();
const db_path = path.join('db', 'database.db');
const db = new sqlite3.Database(db_path);
const dbRun = promisify(db.run.bind(db));
const fsUnlink = promisify(fs.unlink);

app.use(express.static('public'));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(session({
    store: new SQLiteStore({ db: 'sessions.sqlite', dir: 'db' }), 
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: { secure: 'auto', httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000 } 
}));

async function initializeDatabase() {
    return new Promise((resolve, reject) => {
        db.run('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT)', (err) => {
            if (err) {
                console.error('Error creating users table', err);
                reject(err);
            } else {
                resolve();
            }
        });
    });
}

(async () => {
    try {
        await initializeDatabase();
        console.log('Database initialized successfully.');
    } catch (err) {
        console.error('Database initialization failed:', err);
    }
})();

function validateEmail(email) {
    return /^[^@]+@\w+(\.\w+)+\w$/.test(email);
}

function validatePassword(password) {
    return password.length >= 6 && /[a-zA-Z]/.test(password) && /\d/.test(password);
}

app.post('/register', async (req, res) => {
    const { username, password } = req.body;

    if (!validateEmail(username) || !validatePassword(password)) {
        return res.status(400).json({ error: 'Invalid email or password format.' });
    }
    try {
        const hashedPassword = bcrypt.hashSync(password, 8);
        await dbRun('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword]);

        const file_path = path.join('db', 'files', `${username}.txt`);
        await fs.promises.writeFile(file_path, "print('Hello, world')");

        res.json({ message: 'User registered successfully!' });
    } catch (err) {
        if (err.code === 'SQLITE_CONSTRAINT') {
            res.status(500).json({ error: 'Error registering new user, perhaps the username is already taken.' });
        } else {
            res.status(500).send({ error: 'Error creating file'});
        }
    }
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required.' });
    }
    const dbGet = promisify(db.get.bind(db));
    try {
        const user = await dbGet('SELECT * FROM users WHERE username = ?', username);

        if (!user || !bcrypt.compareSync(password, user.password)) {
            return res.status(404).json({ error: 'User not found or password incorrect.' });
        }
        req.session.loggedin = true;
        req.session.username = username;
        res.json({ message: 'User logged in successfully!', username });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ error: 'Error on the server.' });
    }
});


app.post('/logout', async (req, res) => {
    try {
        await new Promise((resolve, reject) => {
            req.session.destroy((err) => {
                if (err) reject(err);
                else resolve();
            });
        });
        res.json({ message: 'User logged out successfully.' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to log out.' });
    }
});

app.post('/deleteuser', async (req, res) => {
    if (!req.session.loggedin) {
        return res.status(400).json({ error: 'User is not logged in.' });
    }
    const username = req.session.username;
    try {
        await dbRun('DELETE FROM users WHERE username = ?', username);     
        const file_path = path.join('db', 'files', `${username}.txt`);
        try {
            await fsUnlink(file_path);
        } catch (err) {
            console.error(`Failed to delete user file for ${username}:`, err);
        }
        await new Promise((resolve, reject) => {
            req.session.destroy(err => {
                if (err) reject(err);
                else resolve();
            });
        });
        res.json({ message: 'User deleted successfully.' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error deleting user.' });
    }
});

app.get('/check', async (req, res) => {
    if (req.session.loggedin) {
        res.json({
            loggedin: true,
            username: req.session.username
        });
    } else {
        res.json({ loggedin: false });
    }
});


app.get('/load', async (req, res) => {
    try {
        const defaultFilename = 'notepad.txt';
        const filePath = req.session.username 
            ? path.join('db', 'files', `${req.session.username}.txt`) 
            : defaultFilename;
        
        // Await on the promise returned by fs.promises.readFile
        const data = await fs.promises.readFile(filePath, 'utf8');
        res.send(data);
    } catch (err) {
        console.error(err); // Logging the error can help in debugging
        res.status(500).send('Error reading file');
    }
});
  
app.post('/save', async (req, res) => {
    const { text } = req.body;
    const defaultFilename = 'notepad.txt';
    const filePath = req.session.username ? path.join('db', 'files', `${req.session.username}.txt`) : defaultFilename;
  
    try {
      await fs.promises.writeFile(filePath, text, 'utf8'); // Write the file with UTF-8 encoding
      res.send('File saved successfully');
    } catch (err) {
      console.error(err); // Log the error for debugging
      res.status(500).send('Error saving file');
    }
});

app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});