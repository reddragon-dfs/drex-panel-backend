
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
const { WebSocketServer } = require('ws');
const http = require('http');
const axios = require('axios');
const fs = require('fs');
const path = require('path');

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Database setup
const db = new sqlite3.Database('./drex.db');

// Initialize database tables
db.serialize(() => {
  // Users table
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'user',
    coins INTEGER DEFAULT 500,
    client_api_key TEXT,
    has_client_key BOOLEAN DEFAULT 0,
    is_banned BOOLEAN DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Servers table
  db.run(`CREATE TABLE IF NOT EXISTS servers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    server_id TEXT NOT NULL,
    server_name TEXT NOT NULL,
    bot_type TEXT,
    ram_type TEXT,
    memory INTEGER,
    disk INTEGER,
    cpu INTEGER,
    status TEXT DEFAULT 'stopped',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id),
    UNIQUE(user_id, server_id)
  )`);

  // Transactions table
  db.run(`CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    type TEXT NOT NULL,
    amount INTEGER NOT NULL,
    balance_after INTEGER NOT NULL,
    description TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);

  // AFK sessions table
  db.run(`CREATE TABLE IF NOT EXISTS afk_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    seconds INTEGER DEFAULT 0,
    earned_today INTEGER DEFAULT 0,
    last_claim DATE,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);

  // Create admin user if not exists
  db.get("SELECT * FROM users WHERE username = 'admin'", async (err, row) => {
    if (!row) {
      const hashedPassword = await bcrypt.hash('admin123', 10);
      db.run("INSERT INTO users (username, email, password, role, coins) VALUES (?, ?, ?, ?, ?)",
        ['admin', 'admin@drex.com', hashedPassword, 'admin', 10000]);
      console.log('Admin user created: admin / admin123');
    }
  });
});

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'drex_panel_super_secret_key_change_me';

// Helper functions
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'Access denied' });
  }
  
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
};

const requireAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

// Add transaction
const addTransaction = (userId, type, amount, balanceAfter, description) => {
  db.run(
    'INSERT INTO transactions (user_id, type, amount, balance_after, description) VALUES (?, ?, ?, ?, ?)',
    [userId, type, amount, balanceAfter, description]
  );
};

// ==================== AUTH ROUTES ====================

app.post('/api/auth/register', async (req, res) => {
  const { username, email, password } = req.body;
  
  if (!username || !email || !password) {
    return res.status(400).json({ error: 'All fields required' });
  }
  
  if (password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  }
  
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    
    db.run(
      'INSERT INTO users (username, email, password, coins) VALUES (?, ?, ?, ?)',
      [username, email, hashedPassword, 500],
      function(err) {
        if (err) {
          if (err.message.includes('UNIQUE')) {
            return res.status(400).json({ error: 'Username or email already exists' });
          }
          return res.status(500).json({ error: 'Registration failed' });
        }
        
        const token = jwt.sign({ id: this.lastID, username, role: 'user' }, JWT_SECRET, { expiresIn: '7d' });
        
        res.json({
          token,
          user: {
            id: this.lastID,
            username,
            email,
            role: 'user',
            coins: 500,
            has_client_key: false
          }
        });
      }
    );
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  
  db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
    if (err || !user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    if (user.is_banned) {
      return res.status(403).json({ error: 'Account banned' });
    }
    
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
    
    res.json({
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
        coins: user.coins,
        has_client_key: !!user.has_client_key
      }
    });
  });
});

app.get('/api/auth/me', authenticateToken, (req, res) => {
  db.get('SELECT id, username, email, role, coins, has_client_key, is_banned FROM users WHERE id = ?', [req.user.id], (err, user) => {
    if (err || !user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json({ user });
  });
});

// ==================== CLIENT API KEY ====================

app.put('/api/user/client-key', authenticateToken, (req, res) => {
  const { clientApiKey } = req.body;
  
  if (!clientApiKey || !clientApiKey.startsWith('ptlc_')) {
    return res.status(400).json({ error: 'Invalid API key format' });
  }
  
  db.run(
    'UPDATE users SET client_api_key = ?, has_client_key = 1 WHERE id = ?',
    [clientApiKey, req.user.id],
    function(err) {
      if (err) {
        return res.status(500).json({ error: 'Failed to save key' });
      }
      res.json({ success: true });
    }
  );
});

// ==================== SERVERS ====================

app.get('/api/servers', authenticateToken, (req, res) => {
  db.all('SELECT * FROM servers WHERE user_id = ? ORDER BY created_at DESC', [req.user.id], (err, servers) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to load servers' });
    }
    res.json({ servers });
  });
});

app.post('/api/servers', authenticateToken, async (req, res) => {
  const { name, ramType } = req.body;
  
  const ramPrices = {
    '5gb': 10,
    '10gb': 50,
    'unli': 100,
    'admin': 250
  };
  
  const cost = ramPrices[ramType];
  if (!cost) {
    return res.status(400).json({ error: 'Invalid RAM type' });
  }
  
  db.get('SELECT coins FROM users WHERE id = ?', [req.user.id], async (err, user) => {
    if (err || !user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    if (user.coins < cost) {
      return res.status(400).json({ error: `Need ${cost - user.coins} more coins` });
    }
    
    // Create mock server (replace with actual Pterodactyl API call)
    const serverId = 'srv_' + Math.random().toString(36).substr(2, 8);
    const newBalance = user.coins - cost;
    
    db.run(
      'INSERT INTO servers (user_id, server_id, server_name, ram_type, memory, disk, cpu, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      [req.user.id, serverId, name, ramType, ramType === '5gb' ? 5120 : ramType === '10gb' ? 10240 : ramType === 'unli' ? 32768 : 65536, 10240, 50, 'stopped'],
      function(err) {
        if (err) {
          return res.status(500).json({ error: 'Failed to create server' });
        }
        
        db.run('UPDATE users SET coins = ? WHERE id = ?', [newBalance, req.user.id]);
        addTransaction(req.user.id, 'deploy', -cost, newBalance, `Deployed ${ramType} server: ${name}`);
        
        res.json({
          success: true,
          newBalance,
          server: {
            id: serverId,
            name,
            ram_type: ramType
          }
        });
      }
    );
  });
});

app.delete('/api/servers/:serverId', authenticateToken, (req, res) => {
  db.run(
    'DELETE FROM servers WHERE server_id = ? AND user_id = ?',
    [req.params.serverId, req.user.id],
    function(err) {
      if (err) {
        return res.status(500).json({ error: 'Failed to delete server' });
      }
      res.json({ success: true });
    }
  );
});

app.post('/api/servers/:serverId/power', authenticateToken, (req, res) => {
  const { action } = req.body;
  // Mock power action - replace with actual Pterodactyl API call
  res.json({ success: true, action });
});

app.get('/api/servers/:serverId/console', authenticateToken, (req, res) => {
  // Return mock WebSocket credentials
  res.json({
    socket: `wss://mock-panel.com/socket/${req.params.serverId}`,
    token: 'mock_token_' + Math.random().toString(36).substr(2, 16)
  });
});

// ==================== AFK ====================

app.get('/api/afk/stats', authenticateToken, (req, res) => {
  const today = new Date().toISOString().split('T')[0];
  
  db.get('SELECT earned_today FROM afk_sessions WHERE user_id = ? AND last_claim = ?', [req.user.id, today], (err, session) => {
    const earnedToday = session ? session.earned_today : 0;
    res.json({
      todayEarned: earnedToday,
      maxDaily: 500,
      remaining: Math.max(0, 500 - earnedToday)
    });
  });
});

app.post('/api/afk/claim', authenticateToken, (req, res) => {
  const { seconds } = req.body;
  const today = new Date().toISOString().split('T')[0];
  const coinsEarned = Math.min(Math.floor(seconds * 0.1), 500);
  
  db.get('SELECT earned_today FROM afk_sessions WHERE user_id = ? AND last_claim = ?', [req.user.id, today], (err, session) => {
    let currentEarned = session ? session.earned_today : 0;
    const canEarn = Math.min(coinsEarned, 500 - currentEarned);
    
    if (canEarn <= 0) {
      return res.status(400).json({ error: 'Daily limit reached' });
    }
    
    db.get('SELECT coins FROM users WHERE id = ?', [req.user.id], (err, user) => {
      const newBalance = user.coins + canEarn;
      
      db.run('UPDATE users SET coins = ? WHERE id = ?', [newBalance, req.user.id]);
      
      if (session) {
        db.run('UPDATE afk_sessions SET earned_today = ? WHERE user_id = ? AND last_claim = ?', [currentEarned + canEarn, req.user.id, today]);
      } else {
        db.run('INSERT INTO afk_sessions (user_id, earned_today, last_claim) VALUES (?, ?, ?)', [req.user.id, canEarn, today]);
      }
      
      addTransaction(req.user.id, 'afk', canEarn, newBalance, `AFK farm: ${Math.floor(seconds)} seconds`);
      
      res.json({
        success: true,
        coinsAdded: canEarn,
        newBalance,
        todayEarned: currentEarned + canEarn,
        remaining: 500 - (currentEarned + canEarn)
      });
    });
  });
});

// ==================== TRANSACTIONS ====================

app.get('/api/transactions', authenticateToken, (req, res) => {
  db.all(
    'SELECT * FROM transactions WHERE user_id = ? ORDER BY created_at DESC LIMIT 100',
    [req.user.id],
    (err, transactions) => {
      res.json({ transactions: transactions || [] });
    }
  );
});

// ==================== ADMIN ROUTES ====================

app.get('/api/admin/stats', authenticateToken, requireAdmin, (req, res) => {
  db.get('SELECT COUNT(*) as total_users FROM users', (err, users) => {
    db.get('SELECT COUNT(*) as total_servers FROM servers', (err, servers) => {
      db.get('SELECT COUNT(*) as running_servers FROM servers WHERE status = "running"', (err, running) => {
        db.get('SELECT SUM(coins) as total_coins FROM users', (err, coins) => {
          res.json({
            total_users: users?.total_users || 0,
            total_servers: servers?.total_servers || 0,
            running_servers: running?.running_servers || 0,
            total_coins: coins?.total_coins || 0
          });
        });
      });
    });
  });
});

app.get('/api/admin/users', authenticateToken, requireAdmin, (req, res) => {
  db.all('SELECT id, username, email, role, coins, has_client_key, is_banned FROM users', (err, users) => {
    res.json({ users: users || [] });
  });
});

app.get('/api/admin/servers', authenticateToken, requireAdmin, (req, res) => {
  db.all(`
    SELECT s.*, u.username 
    FROM servers s 
    JOIN users u ON s.user_id = u.id 
    ORDER BY s.created_at DESC
  `, (err, servers) => {
    res.json({ servers: servers || [] });
  });
});

app.post('/api/admin/users/:userId/coins', authenticateToken, requireAdmin, (req, res) => {
  const { amount, reason } = req.body;
  
  db.get('SELECT coins FROM users WHERE id = ?', [req.params.userId], (err, user) => {
    const newBalance = user.coins + amount;
    
    db.run('UPDATE users SET coins = ? WHERE id = ?', [newBalance, req.params.userId]);
    addTransaction(req.params.userId, 'admin', amount, newBalance, reason || 'Admin adjustment');
    
    res.json({ success: true, newBalance });
  });
});

app.put('/api/admin/users/:userId', authenticateToken, requireAdmin, (req, res) => {
  const { is_banned } = req.body;
  
  db.run('UPDATE users SET is_banned = ? WHERE id = ?', [is_banned ? 1 : 0, req.params.userId], (err) => {
    res.json({ success: true });
  });
});

// ==================== WEBSOCKET HANDLER ====================

wss.on('connection', (ws, req) => {
  console.log('WebSocket client connected');
  
  ws.on('message', (message) => {
    try {
      const data = JSON.parse(message);
      // Handle console commands, file operations, etc.
      ws.send(JSON.stringify({ event: 'console output', args: ['Connected to server'] }));
    } catch (error) {
      console.error('WebSocket error:', error);
    }
  });
  
  ws.send(JSON.stringify({ event: 'auth success' }));
});

// ==================== HEALTH CHECK ====================

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ==================== START SERVER ====================

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`DREX PANEL Backend running on port ${PORT}`);
  console.log(`WebSocket server ready`);
});
