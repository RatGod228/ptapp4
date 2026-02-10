const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// Load nodemailer
let nodemailer = null;
try {
  nodemailer = require('nodemailer');
} catch (e) {
  console.log('Nodemailer not installed, emails will be logged only');
}

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
const DATA_DIR = process.env.DATA_DIR || '/tmp/data';

// Email configuration from environment variables
const SMTP_HOST = process.env.SMTP_HOST;
const SMTP_PORT = process.env.SMTP_PORT || 587;
const SMTP_USER = process.env.SMTP_USER;
const SMTP_PASS = process.env.SMTP_PASS;
const SMTP_FROM = process.env.SMTP_FROM || 'noreply@profittrack.app';

console.log('=== ProfitTrack Server Starting ===');
console.log('Data directory:', DATA_DIR);
console.log('SMTP configured:', SMTP_HOST ? 'Yes' : 'No');

// Ensure data directory exists
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

// Database files
const DB = {
  users: path.join(DATA_DIR, 'users.json'),
  purchases: path.join(DATA_DIR, 'purchases.json'),
  sales: path.join(DATA_DIR, 'sales.json'),
  branches: path.join(DATA_DIR, 'branches.json'),
  resetCodes: path.join(DATA_DIR, 'resetCodes.json'),
  reviews: path.join(DATA_DIR, 'reviews.json')
};

// Initialize DB files
Object.values(DB).forEach(file => {
  if (!fs.existsSync(file)) {
    fs.writeFileSync(file, '[]');
    console.log('Created:', path.basename(file));
  }
});

// Create email transporter if SMTP is configured
let emailTransporter = null;
if (nodemailer && SMTP_HOST && SMTP_USER && SMTP_PASS) {
  emailTransporter = nodemailer.createTransport({
    host: SMTP_HOST,
    port: parseInt(SMTP_PORT),
    secure: parseInt(SMTP_PORT) === 465,
    auth: { user: SMTP_USER, pass: SMTP_PASS }
  });
  console.log('Email transporter configured');
} else {
  console.log('Email: Logging only mode (configure SMTP_HOST, SMTP_USER, SMTP_PASS for real emails)');
}

// Send email function
const sendEmail = async (to, subject, text) => {
  const emailLog = {
    id: crypto.randomUUID(),
    to,
    subject,
    sentAt: new Date().toISOString(),
    sent: false
  };
  
  if (emailTransporter) {
    try {
      await emailTransporter.sendMail({
        from: `"ProfitTrack" <${SMTP_FROM}>`,
        to,
        subject,
        text,
        html: text.replace(/\n/g, '<br>')
      });
      emailLog.sent = true;
      console.log('Email sent to:', to);
    } catch (err) {
      console.error('Email failed:', err.message);
    }
  } else {
    console.log('Email (not sent - no SMTP):', { to, subject });
  }
  
  return emailLog;
};

// Password hashing
const hashPassword = (pwd) => crypto.createHash('sha256').update(pwd + JWT_SECRET).digest('hex');

// JWT functions
const generateToken = (user) => {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(JSON.stringify({ 
    id: user.id, 
    login: user.login, 
    email: user.email, 
    name: user.name, 
    iat: Date.now(),
    exp: Date.now() + 7 * 24 * 60 * 60 * 1000 // 7 days
  })).toString('base64url');
  const signature = crypto.createHmac('sha256', JWT_SECRET).update(header + '.' + payload).digest('base64url');
  return header + '.' + payload + '.' + signature;
};

const verifyToken = (token) => {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const expected = crypto.createHmac('sha256', JWT_SECRET).update(parts[0] + '.' + parts[1]).digest('base64url');
    if (parts[2] !== expected) return null;
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
    if (payload.exp && payload.exp < Date.now()) return null;
    return payload;
  } catch (e) { return null; }
};

// CORS headers
const setCORS = (res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
};

// Parse request body
const parseBody = (req) => new Promise((resolve, reject) => {
  let body = '';
  req.on('data', chunk => body += chunk);
  req.on('end', () => {
    try { resolve(body ? JSON.parse(body) : {}); } 
    catch (e) { reject(e); }
  });
});

// Get authenticated user
const getAuthUser = (req) => {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return null;
  const decoded = verifyToken(auth.substring(7));
  if (!decoded) return null;
  const users = JSON.parse(fs.readFileSync(DB.users, 'utf8') || '[]');
  return users.find(u => u.id === decoded.id);
};

// DB helpers
const readDB = (dbName) => {
  try { return JSON.parse(fs.readFileSync(DB[dbName], 'utf8') || '[]'); } 
  catch (e) { return []; }
};

const writeDB = (dbName, data) => {
  fs.writeFileSync(DB[dbName], JSON.stringify(data, null, 2));
};

// API Routes
const routes = {
  // Auth routes
  'POST /api/auth/register': async (req, res) => {
    const { name, login, password, email } = await parseBody(req);
    if (!name || !login || !password) {
      res.writeHead(400); 
      return res.end(JSON.stringify({ error: 'Заполните все поля' }));
    }
    if (!email) {
      res.writeHead(400); 
      return res.end(JSON.stringify({ error: 'Email обязателен для восстановления пароля' }));
    }
    
    const users = readDB('users');
    if (users.find(u => u.login === login)) {
      res.writeHead(400); 
      return res.end(JSON.stringify({ error: 'Логин уже занят' }));
    }
    if (users.find(u => u.email === email)) {
      res.writeHead(400); 
      return res.end(JSON.stringify({ error: 'Email уже используется' }));
    }
    
    const newUser = { 
      id: crypto.randomUUID(), 
      name, 
      login, 
      email, 
      password: hashPassword(password), 
      createdAt: new Date().toISOString() 
    };
    users.push(newUser);
    writeDB('users', users);
    
    const token = generateToken(newUser);
    res.writeHead(201); 
    res.end(JSON.stringify({ 
      token, 
      user: { id: newUser.id, name, login, email } 
    }));
  },
  
  'POST /api/auth/login': async (req, res) => {
    const { login, password } = await parseBody(req);
    const users = readDB('users');
    const user = users.find(u => u.login === login && u.password === hashPassword(password));
    if (!user) {
      res.writeHead(401); 
      return res.end(JSON.stringify({ error: 'Неверный логин или пароль' }));
    }
    const token = generateToken(user);
    res.writeHead(200); 
    res.end(JSON.stringify({ 
      token, 
      user: { id: user.id, name: user.name, login: user.login, email: user.email } 
    }));
  },
  
  'POST /api/auth/forgot-password': async (req, res) => {
    const { email } = await parseBody(req);
    const users = readDB('users');
    const user = users.find(u => u.email === email);
    if (!user) {
      res.writeHead(404); 
      return res.end(JSON.stringify({ error: 'Пользователь с таким email не найден' }));
    }
    
    const code = Math.random().toString(36).substring(2, 8).toUpperCase();
    const resetCodes = readDB('resetCodes');
    const filtered = resetCodes.filter(c => c.email !== email);
    filtered.push({ email, code, expiresAt: Date.now() + 15 * 60 * 1000 }); // 15 min
    writeDB('resetCodes', filtered);
    
    // Send real email
    await sendEmail(
      email, 
      'Восстановление пароля - ProfitTrack', 
      `Здравствуйте, ${user.name}!\n\nВы запросили восстановление пароля для ProfitTrack.\n\nВаш код подтверждения: ${code}\n\nКод действителен в течение 15 минут.\n\nЕсли вы не запрашивали восстановление пароля, проигнорируйте это письмо.`
    );
    
    res.writeHead(200); 
    res.end(JSON.stringify({ message: 'Код отправлен на ваш email' }));
  },
  
  'POST /api/auth/verify-code': async (req, res) => {
    const { email, code } = await parseBody(req);
    const resetCodes = readDB('resetCodes');
    const resetCode = resetCodes.find(c => c.email === email && c.code === code.toUpperCase());
    if (!resetCode || Date.now() > resetCode.expiresAt) {
      res.writeHead(400); 
      return res.end(JSON.stringify({ error: 'Неверный или просроченный код' }));
    }
    res.writeHead(200); 
    res.end(JSON.stringify({ message: 'Код подтвержден' }));
  },
  
  'POST /api/auth/reset-password': async (req, res) => {
    const { email, code, newPassword } = await parseBody(req);
    if (!newPassword || newPassword.length < 4) {
      res.writeHead(400); 
      return res.end(JSON.stringify({ error: 'Пароль должен быть минимум 4 символа' }));
    }
    
    const resetCodes = readDB('resetCodes');
    const resetCode = resetCodes.find(c => c.email === email && c.code === code.toUpperCase());
    if (!resetCode || Date.now() > resetCode.expiresAt) {
      res.writeHead(400); 
      return res.end(JSON.stringify({ error: 'Неверный или просроченный код' }));
    }
    
    const users = readDB('users');
    const idx = users.findIndex(u => u.email === email);
    if (idx === -1) {
      res.writeHead(404); 
      return res.end(JSON.stringify({ error: 'Пользователь не найден' }));
    }
    
    users[idx].password = hashPassword(newPassword);
    writeDB('users', users);
    writeDB('resetCodes', resetCodes.filter(c => c.code !== code.toUpperCase()));
    
    res.writeHead(200); 
    res.end(JSON.stringify({ message: 'Пароль успешно изменен' }));
  },
  
  'POST /api/auth/change-password': async (req, res) => {
    const user = getAuthUser(req);
    if (!user) {
      res.writeHead(401); 
      return res.end(JSON.stringify({ error: 'Не авторизован' }));
    }
    
    const { currentPassword, newPassword } = await parseBody(req);
    if (!currentPassword || !newPassword || newPassword.length < 4) {
      res.writeHead(400); 
      return res.end(JSON.stringify({ error: 'Заполните все поля, пароль минимум 4 символа' }));
    }
    
    const users = readDB('users');
    const idx = users.findIndex(u => u.id === user.id);
    if (users[idx].password !== hashPassword(currentPassword)) {
      res.writeHead(400); 
      return res.end(JSON.stringify({ error: 'Текущий пароль неверный' }));
    }
    
    users[idx].password = hashPassword(newPassword);
    writeDB('users', users);
    res.writeHead(200); 
    res.end(JSON.stringify({ message: 'Пароль изменен' }));
  },
  
  // User routes
  'GET /api/user/profile': async (req, res) => {
    const user = getAuthUser(req);
    if (!user) {
      res.writeHead(401); 
      return res.end(JSON.stringify({ error: 'Не авторизован' }));
    }
    res.writeHead(200); 
    res.end(JSON.stringify({ 
      id: user.id, 
      name: user.name, 
      login: user.login, 
      email: user.email 
    }));
  },
  
  'PUT /api/user/profile': async (req, res) => {
    const user = getAuthUser(req);
    if (!user) {
      res.writeHead(401); 
      return res.end(JSON.stringify({ error: 'Не авторизован' }));
    }
    
    const { name, email } = await parseBody(req);
    const users = readDB('users');
    const idx = users.findIndex(u => u.id === user.id);
    
    if (email && email !== user.email) {
      if (users.find(u => u.email === email && u.id !== user.id)) {
        res.writeHead(400); 
        return res.end(JSON.stringify({ error: 'Email уже используется' }));
      }
      users[idx].email = email;
    }
    if (name) users[idx].name = name;
    
    writeDB('users', users);
    res.writeHead(200); 
    res.end(JSON.stringify({ 
      id: users[idx].id, 
      name: users[idx].name, 
      login: users[idx].login, 
      email: users[idx].email 
    }));
  },
  
  // Branches routes
  'GET /api/branches': async (req, res) => {
    const user = getAuthUser(req);
    if (!user) {
      res.writeHead(401); 
      return res.end(JSON.stringify({ error: 'Не авторизован' }));
    }
    const branches = readDB('branches').filter(b => b.userId === user.id);
    res.writeHead(200); 
    res.end(JSON.stringify(branches));
  },
  
  'POST /api/branches': async (req, res) => {
    const user = getAuthUser(req);
    if (!user) {
      res.writeHead(401); 
      return res.end(JSON.stringify({ error: 'Не авторизован' }));
    }
    
    const { name } = await parseBody(req);
    if (!name) {
      res.writeHead(400); 
      return res.end(JSON.stringify({ error: 'Название обязательно' }));
    }
    
    const branches = readDB('branches');
    const newBranch = { 
      id: crypto.randomUUID(), 
      userId: user.id,
      name, 
      createdAt: new Date().toISOString() 
    };
    branches.push(newBranch);
    writeDB('branches', branches);
    res.writeHead(201); 
    res.end(JSON.stringify(newBranch));
  },
  
  'DELETE /api/branches/:id': async (req, res, id) => {
    const user = getAuthUser(req);
    if (!user) {
      res.writeHead(401); 
      return res.end(JSON.stringify({ error: 'Не авторизован' }));
    }
    
    const branches = readDB('branches');
    const userBranches = branches.filter(b => b.userId === user.id);
    if (userBranches.length <= 1) {
      res.writeHead(400); 
      return res.end(JSON.stringify({ error: 'Нельзя удалить последнюю ветку' }));
    }
    
    writeDB('branches', branches.filter(b => b.id !== id || b.userId !== user.id));
    
    // Also delete related purchases and sales
    const purchases = readDB('purchases');
    writeDB('purchases', purchases.filter(p => p.branchId !== id || p.userId !== user.id));
    
    const sales = readDB('sales');
    writeDB('sales', sales.filter(s => s.branchId !== id || s.userId !== user.id));
    
    res.writeHead(200); 
    res.end(JSON.stringify({ message: 'Ветка удалена' }));
  },
  
  // Purchases routes
  'GET /api/purchases': async (req, res) => {
    const user = getAuthUser(req);
    if (!user) {
      res.writeHead(401); 
      return res.end(JSON.stringify({ error: 'Не авторизован' }));
    }
    const purchases = readDB('purchases').filter(p => p.userId === user.id);
    res.writeHead(200); 
    res.end(JSON.stringify(purchases));
  },
  
  'POST /api/purchases': async (req, res) => {
    const user = getAuthUser(req);
    if (!user) {
      res.writeHead(401); 
      return res.end(JSON.stringify({ error: 'Не авторизован' }));
    }
    
    const { productName, quantity, price, date, branchId, photo, notes } = await parseBody(req);
    if (!productName || !quantity || !price || !branchId) {
      res.writeHead(400); 
      return res.end(JSON.stringify({ error: 'Заполните обязательные поля' }));
    }
    
    const qty = parseInt(quantity);
    const purchases = readDB('purchases');
    const newPurchase = {
      id: crypto.randomUUID(),
      userId: user.id,
      productName: productName.trim(),
      quantity: qty,
      remainingQty: qty,
      price: parseFloat(price),
      total: qty * parseFloat(price),
      date: date || new Date().toISOString().split('T')[0],
      branchId,
      photo: photo || undefined,
      notes: notes ? notes.trim() : undefined,
      createdAt: new Date().toISOString()
    };
    purchases.push(newPurchase);
    writeDB('purchases', purchases);
    res.writeHead(201); 
    res.end(JSON.stringify(newPurchase));
  },
  
  'DELETE /api/purchases/:id': async (req, res, id) => {
    const user = getAuthUser(req);
    if (!user) {
      res.writeHead(401); 
      return res.end(JSON.stringify({ error: 'Не авторизован' }));
    }
    const purchases = readDB('purchases');
    writeDB('purchases', purchases.filter(p => p.id !== id || p.userId !== user.id));
    res.writeHead(200); 
    res.end(JSON.stringify({ message: 'Закупка удалена' }));
  },
  
  'PUT /api/purchases/:id/notes': async (req, res, id) => {
    const user = getAuthUser(req);
    if (!user) {
      res.writeHead(401); 
      return res.end(JSON.stringify({ error: 'Не авторизован' }));
    }
    
    const { notes } = await parseBody(req);
    const purchases = readDB('purchases');
    const idx = purchases.findIndex(p => p.id === id && p.userId === user.id);
    if (idx === -1) {
      res.writeHead(404); 
      return res.end(JSON.stringify({ error: 'Не найдено' }));
    }
    purchases[idx].notes = notes ? notes.trim() : undefined;
    writeDB('purchases', purchases);
    res.writeHead(200); 
    res.end(JSON.stringify(purchases[idx]));
  },
  
  // Sales routes
  'GET /api/sales': async (req, res) => {
    const user = getAuthUser(req);
    if (!user) {
      res.writeHead(401); 
      return res.end(JSON.stringify({ error: 'Не авторизован' }));
    }
    const sales = readDB('sales').filter(s => s.userId === user.id);
    res.writeHead(200); 
    res.end(JSON.stringify(sales));
  },
  
  'POST /api/sales': async (req, res) => {
    const user = getAuthUser(req);
    if (!user) {
      res.writeHead(401); 
      return res.end(JSON.stringify({ error: 'Не авторизован' }));
    }
    
    const { productName, quantity, salePrice, date, branchId, notes } = await parseBody(req);
    if (!productName || !quantity || !salePrice || !branchId) {
      res.writeHead(400); 
      return res.end(JSON.stringify({ error: 'Заполните обязательные поля' }));
    }
    
    const qty = parseInt(quantity);
    const sPrice = parseFloat(salePrice);
    
    // Get purchases for this product (FIFO)
    const purchases = readDB('purchases');
    const relevantPurchases = purchases.filter(p => 
      p.userId === user.id &&
      p.branchId === branchId && 
      p.productName === productName && 
      p.remainingQty > 0
    ).sort((a, b) => new Date(a.date) - new Date(b.date));
    
    const totalRemaining = relevantPurchases.reduce((sum, p) => sum + p.remainingQty, 0);
    if (totalRemaining < qty) {
      res.writeHead(400); 
      return res.end(JSON.stringify({ error: `Недостаточно товара! Осталось: ${totalRemaining} шт.` }));
    }
    
    // Deduct from purchases (FIFO)
    let remainingToDeduct = qty;
    const updatedPurchases = purchases.map(p => {
      if (remainingToDeduct <= 0) return p;
      if (p.userId !== user.id || p.branchId !== branchId || p.productName !== productName || p.remainingQty <= 0) return p;
      const deductQty = Math.min(p.remainingQty, remainingToDeduct);
      remainingToDeduct -= deductQty;
      return { ...p, remainingQty: p.remainingQty - deductQty };
    });
    
    writeDB('purchases', updatedPurchases);
    
    const firstPurchase = relevantPurchases[0];
    const purchasePrice = firstPurchase?.price || 0;
    
    const newSale = {
      id: crypto.randomUUID(),
      userId: user.id,
      productName: productName.trim(),
      quantity: qty,
      purchasePrice: purchasePrice,
      salePrice: sPrice,
      totalCost: qty * purchasePrice,
      totalRevenue: qty * sPrice,
      profit: qty * (sPrice - purchasePrice),
      date: date || new Date().toISOString().split('T')[0],
      branchId,
      purchaseId: firstPurchase?.id || '',
      photo: firstPurchase?.photo,
      notes: notes ? notes.trim() : undefined,
      createdAt: new Date().toISOString()
    };
    
    const sales = readDB('sales');
    sales.push(newSale);
    writeDB('sales', sales);
    res.writeHead(201); 
    res.end(JSON.stringify(newSale));
  },
  
  'DELETE /api/sales/:id': async (req, res, id) => {
    const user = getAuthUser(req);
    if (!user) {
      res.writeHead(401); 
      return res.end(JSON.stringify({ error: 'Не авторизован' }));
    }
    const sales = readDB('sales');
    writeDB('sales', sales.filter(s => s.id !== id || s.userId !== user.id));
    res.writeHead(200); 
    res.end(JSON.stringify({ message: 'Продажа удалена' }));
  },
  
  'PUT /api/sales/:id/notes': async (req, res, id) => {
    const user = getAuthUser(req);
    if (!user) {
      res.writeHead(401); 
      return res.end(JSON.stringify({ error: 'Не авторизован' }));
    }
    
    const { notes } = await parseBody(req);
    const sales = readDB('sales');
    const idx = sales.findIndex(s => s.id === id && s.userId === user.id);
    if (idx === -1) {
      res.writeHead(404); 
      return res.end(JSON.stringify({ error: 'Не найдено' }));
    }
    sales[idx].notes = notes ? notes.trim() : undefined;
    writeDB('sales', sales);
    res.writeHead(200); 
    res.end(JSON.stringify(sales[idx]));
  },
  
  // Reviews routes
  'GET /api/reviews': async (req, res) => {
    const reviews = readDB('reviews').sort((a, b) => new Date(b.date) - new Date(a.date));
    res.writeHead(200); 
    res.end(JSON.stringify(reviews));
  },
  
  'POST /api/reviews': async (req, res) => {
    const user = getAuthUser(req);
    if (!user) {
      res.writeHead(401); 
      return res.end(JSON.stringify({ error: 'Не авторизован' }));
    }
    
    const { rating, text } = await parseBody(req);
    if (!rating || rating < 1 || rating > 5) {
      res.writeHead(400); 
      return res.end(JSON.stringify({ error: 'Выберите рейтинг' }));
    }
    if (!text || !text.trim()) {
      res.writeHead(400); 
      return res.end(JSON.stringify({ error: 'Напишите отзыв' }));
    }
    
    const reviews = readDB('reviews');
    const newReview = {
      id: crypto.randomUUID(),
      userId: user.id,
      name: user.name,
      rating,
      text: text.trim(),
      date: new Date().toISOString().split('T')[0]
    };
    reviews.push(newReview);
    writeDB('reviews', reviews);
    res.writeHead(201); 
    res.end(JSON.stringify(newReview));
  }
};

// Serve static files
const serveStatic = (req, res) => {
  const url = req.url === '/' ? '/index.html' : req.url;
  const filePath = path.join(__dirname, 'public', url);
  try {
    const content = fs.readFileSync(filePath);
    const ext = path.extname(filePath);
    const contentType = { 
      '.html': 'text/html', 
      '.js': 'application/javascript', 
      '.css': 'text/css',
      '.json': 'application/json'
    }[ext] || 'application/octet-stream';
    res.writeHead(200, { 'Content-Type': contentType });
    res.end(content);
  } catch (e) {
    // Serve index.html for client-side routing
    try {
      const indexContent = fs.readFileSync(path.join(__dirname, 'public', 'index.html'));
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(indexContent);
    } catch (e2) {
      res.writeHead(404); 
      res.end('Not found');
    }
  }
};

// Create server
const server = http.createServer(async (req, res) => {
  setCORS(res);
  if (req.method === 'OPTIONS') { 
    res.writeHead(200); 
    return res.end(); 
  }
  
  const pathname = req.url.split('?')[0];
  
  // Check for parameterized routes
  for (const routeKey of Object.keys(routes)) {
    const [method, pathPattern] = routeKey.split(' ');
    if (req.method === method) {
      // Handle /api/branches/:id pattern
      if (pathPattern.includes('/:')) {
        const basePath = pathPattern.split('/:')[0];
        if (pathname.startsWith(basePath + '/')) {
          const id = pathname.substring(basePath.length + 1);
          try {
            await routes[routeKey](req, res, id);
            return;
          } catch (e) {
            console.error('Route error:', e);
            res.writeHead(500); 
            return res.end(JSON.stringify({ error: 'Server error' }));
          }
        }
      } else if (pathname === pathPattern) {
        try {
          await routes[routeKey](req, res);
          return;
        } catch (e) {
          console.error('Route error:', e);
          res.writeHead(500); 
          return res.end(JSON.stringify({ error: 'Server error' }));
        }
      }
    }
  }
  
  serveStatic(req, res);
});

server.listen(PORT, () => {
  console.log('Server running on port', PORT);
  console.log('JWT Secret:', JWT_SECRET.substring(0, 10) + '...');
});
