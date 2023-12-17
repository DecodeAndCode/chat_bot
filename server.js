const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const axios = require('axios');
const mongoose = require('mongoose');

const app = express();
const port = 3000;

const secret = 'your_secret_key';
const openAIAPIKEY = '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';

mongoose.connect('mongodb+srv://chiranjeevkundu2000:A0YCDIACGF44eWyI@cluster0.rrjm2bq.mongodb.net/', { dbName: "chatbot_db" });

const userSchema = new mongoose.Schema({
    username: { type: String, unique: true, required: true },
    password: { type: String, required: true },
});

const adminSchema = new mongoose.Schema({
    username: { type: String, unique: true, required: true },
    password: { type: String, required: true },
});

const User = mongoose.model('User', userSchema);
const Admin = mongoose.model('Admin', adminSchema);

app.use(bodyParser.json());


// User Routes
app.post('/api/signup', async (req, res) => {
    const { username, password } = req.body;

    try {
        const existingUser = await User.findOne({ username });

        if (existingUser) {
            return res.status(400).json({ error: 'Username already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = new User({ username, password: hashedPassword });
        await newUser.save();

        const token = generateToken(newUser);
        res.json({ token });
    } catch (error) {
        res.status(500).json({ error: error.toString() });
    }
});

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        const user = await User.findOne({ username });

        if (!user) {
            return res.status(401).json({ error: 'Invalid username or password' });
        }

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid username or password' });
        }

        const token = generateToken(user);
        res.json({ token });
    } catch (error) {
        res.status(500).json({ error: error.toString() });
    }
});

app.post('/api/chatbot', authenticateToken, async (req, res) => {
    const { prompt } = req.body;

    try {
        const response = await chatGPTAPI(prompt);
        res.json({ response });
    } catch (error) {
        res.status(500).json({ error: error.toString() });
    }
});

//Admin Routes
app.post('/api/admin/signup', async (req, res) => {
    const { username, password } = req.body;

    try {
        const existingAdmin = await Admin.findOne({ username });

        if (existingAdmin) {
            return res.status(400).json({ error: 'Admin username already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const newAdmin = new Admin({ username, password: hashedPassword });
        await newAdmin.save();

        const token = generateToken(newAdmin);
        res.json({ token });
    } catch (error) {
        res.status(500).json({ error: error.toString() });
    }
});

app.post('/api/admin/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        const admin = await Admin.findOne({ username });

        if (!admin) {
            return res.status(401).json({ error: 'Invalid admin username or password' });
        }

        const validPassword = await bcrypt.compare(password, admin.password);
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid admin username or password' });
        }

        const token = generateToken(admin);
        res.json({ token });
    } catch (error) {
        res.status(500).json({ error: error.toString() });
    }
});

app.get('/api/admin/control-panel', authenticateAdminToken, async (req, res) => {
    try {
        const users = await User.find({}, 'username');

        res.json({ users });
    } catch (error) {
        res.status(500).json({ error: error.toString() });
    }
});

app.get('/api/admin/user/:userId', authenticateAdminToken, async (req, res) => {
    const userId = req.params.userId;

    try {
        const user = await User.findById(userId);

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json({ user });
    } catch (error) {
        res.status(500).json({ error: error.toString() });
    }
});

app.put('/api/admin/user/:userId', authenticateAdminToken, async (req, res) => {
    const userId = req.params.userId;
    const { username, password } = req.body;

    try {
        const updatedUser = await User.findByIdAndUpdate(userId, { username, password }, { new: true });

        if (!updatedUser) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json({ user: updatedUser });
    } catch (error) {
        res.status(500).json({ error: error.toString() });
    }
});

app.delete('/api/admin/user/:userId', authenticateAdminToken, async (req, res) => {
    const userId = req.params.userId;

    try {
        const deletedUser = await User.findByIdAndDelete(userId);

        if (!deletedUser) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json({ message: 'User deleted successfully' });
    } catch (error) {
        res.status(500).json({ error: error.toString() });
    }
});

function generateToken(user) {
    return jwt.sign({ username: user.username }, secret, { expiresIn: '1h' });
}

function authenticateToken(req, res, next) {
    const token = req.header('Authorization');

    if (!token) {
        return res.status(401).json({ error: 'Access denied' });
    }

    jwt.verify(token, secret, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid token' });
        }

        req.user = user;
        next();
    });
}

function authenticateAdminToken(req, res, next) {
    const token = req.header('Admin-Authorization');

    if (!token) {
        return res.status(401).json({ error: 'Admin access denied' });
    }

    jwt.verify(token, secret, (err, admin) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid admin token' });
        }

        req.admin = admin;
        next();
    });
}

async function chatGPTAPI(prompt) {
    try {
        const response = await axios.post(
            'https://api.openai.com/v1/chat/completions',
            {
                model: 'gpt-3.5-turbo',
                messages: [{ role: 'user', content: prompt }],
            },
            {
                headers: {
                    'Content-Type': 'application/json',
                    Authorization: `Bearer ${openAIAPIKEY}`,
                },
            }
        );

        if (response.status === 200) {
            const content = response.data.choices[0].message.content.trim();
            return content;
        }

        return 'An internal error occurred';
    } catch (e) {
        throw e;
    }
}

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
