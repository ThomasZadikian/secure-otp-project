require('dotenv').config();
const fs = require('fs');
const https = require('https');
const express = require('express');
const session = require('express-session');
const Database = require('better-sqlite3');
const bcrypt = require('bcrypt');
const qrcode = require('qrcode');
const { authenticator } = require('otplib');
const bodyParser = require('body-parser');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const winston = require('winston');

const app = express();
const db = new Database('./data/users.db');


const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
    ),
    transports: [
        new winston.transports.File({ filename: 'logs/security.log' }),
        new winston.transports.Console() 
    ]
});

app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"], 
            scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'", "https://unpkg.com"],
            imgSrc: ["'self'", "data:"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            frameAncestors: ["'none'"], 
            upgradeInsecureRequests: [],
        },
    },
}));

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 10, 
    message: { success: false, message: 'Trop de tentatives IP. Attendez 15 min.' },
    handler: (req, res) => {
        logger.warn(`BRUTE FORCE IP BLOQUÉE: ${req.ip}`);
        res.status(429).json({ success: false, message: 'Trop de tentatives IP.' });
    }
});

app.use(bodyParser.json());
app.use(express.static('public'));
app.use(session({
    secret: process.env.SESSION_SECRET || 'dev_secret',
    resave: false,
    saveUninitialized: false,
    name: 'sessionId',
    cookie: { httpOnly: true, secure: true, sameSite: 'strict' }
}));


db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE,
    password TEXT,
    secret_2fa TEXT,
    is_2fa_active INTEGER DEFAULT 0,
    backup_codes TEXT,
    failed_attempts INTEGER DEFAULT 0,
    locked_until INTEGER DEFAULT NULL
  )
`);


app.get('/api/session', (req, res) => {
    if (!req.session.userId) return res.json({ status: 'guest' });
    if (!req.session.isFullyAuthenticated) return res.json({ status: 'partial' });
    
    const user = db.prepare('SELECT is_2fa_active FROM users WHERE id = ?').get(req.session.userId);
    return res.json({ 
        status: 'authenticated', 
        email: req.session.email, 
        is2faActive: !!user.is_2fa_active 
    });
});

app.post('/api/register', async (req, res) => {
    const { email, password } = req.body;
    try {
        const hash = await bcrypt.hash(password, 10);
        const stmt = db.prepare('INSERT INTO users (email, password) VALUES (?, ?)');
        const info = stmt.run(email, hash);
        
        req.session.userId = info.lastInsertRowid;
        req.session.email = email;
        req.session.isFullyAuthenticated = true;

        logger.info(`NOUVEAU COMPTE: ${email} (IP: ${req.ip})`);
        
        res.json({ success: true, status: 'authenticated' });
    } catch (e) {
        logger.error(`ERREUR INSCRIPTION: ${email} - ${e.message}`);
        res.json({ success: false, message: 'Erreur création compte.' });
    }
});

app.post('/api/login', authLimiter, async (req, res) => {
    const { email, password } = req.body;
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);

    if (!user) {
        logger.warn(`LOGIN ÉCHOUÉ (Inconnu): ${email} (IP: ${req.ip})`);
        return res.json({ success: false, message: 'Identifiants incorrects' });
    }

    if (user.locked_until && user.locked_until > Date.now()) {
        const minutesLeft = Math.ceil((user.locked_until - Date.now()) / 60000);
        logger.warn(`LOGIN BLOQUÉ (Tentative sur compte gelé): ${email}`);
        return res.json({ success: false, message: `Compte verrouillé. Réessayez dans ${minutesLeft} min.` });
    }

    if (await bcrypt.compare(password, user.password)) {
        db.prepare('UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?').run(user.id);
        
        req.session.userId = user.id;
        req.session.email = user.email;
        
        if (user.is_2fa_active) {
            req.session.isFullyAuthenticated = false;
            logger.info(`LOGIN PARTIEL (Mdp OK, attente A2F): ${email}`);
            res.json({ status: 'partial' });
        } else {
            req.session.isFullyAuthenticated = true;
            logger.info(`LOGIN SUCCÈS: ${email}`);
            res.json({ status: 'authenticated' });
        }
    } else {
        const newAttempts = (user.failed_attempts || 0) + 1;
        
        if (newAttempts >= 5) {
            const lockTime = Date.now() + 3600000;
            db.prepare('UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?')
              .run(newAttempts, lockTime, user.id);
            
            logger.warn(`COMPTE VERROUILLÉ (5 échecs): ${email} (IP: ${req.ip})`);
            res.json({ success: false, message: 'Trop d\'échecs. Compte verrouillé pour 1h.' });
        } else {
            db.prepare('UPDATE users SET failed_attempts = ? WHERE id = ?').run(newAttempts, user.id);
            logger.warn(`LOGIN ÉCHOUÉ (Mdp Faux): ${email} - Tentative ${newAttempts}/5`);
            res.json({ success: false, message: 'Identifiants incorrects' });
        }
    }
});

app.post('/api/verify-otp', authLimiter, async (req, res) => {
    if (!req.session.userId) return res.status(403).json({ message: 'Non connecté' });
    const { token, type } = req.body;
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.userId);
    
    let isValid = false;
    let methodUsed = '';

    if (type === 'app') {
        isValid = authenticator.check(token, user.secret_2fa);
        methodUsed = 'application';
    } else if (type === 'backup' && user.backup_codes) {
        const storedHashes = JSON.parse(user.backup_codes);
        for (let i = 0; i < storedHashes.length; i++) {
            if (await bcrypt.compare(token, storedHashes[i])) {
                isValid = true;
                methodUsed = 'backup';
                const newHashes = storedHashes.filter((_, idx) => idx !== i);
                db.prepare('UPDATE users SET backup_codes = ? WHERE id = ?').run(JSON.stringify(newHashes), user.id);
                break;
            }
        }
    }

    if (isValid) {
        req.session.isFullyAuthenticated = true;
        logger.info(`A2F VALIDÉE (${methodUsed}): ${req.session.email}`);
        res.json({ success: true, method: methodUsed });
    } else {
        logger.warn(`A2F ÉCHOUÉE: ${req.session.email}`);
        res.json({ success: false, message: 'Code invalide.' });
    }
});


app.get('/api/setup-2fa', async (req, res) => {
    if (!req.session.userId) return res.status(403).send();
    const secret = authenticator.generateSecret();
    const otpauth = authenticator.keyuri(req.session.email, 'MonAppSecurisee', secret);
    const imageUrl = await qrcode.toDataURL(otpauth);
    req.session.tempSecret = secret;
    res.json({ qrCode: imageUrl, secret: secret });
});

app.post('/api/confirm-2fa', authLimiter, async (req, res) => {
    const { token } = req.body;
    const secret = req.session.tempSecret;
    if (authenticator.check(token, secret)) {
        const backupCodes = Array.from({length: 5}, () => Math.random().toString(36).substr(2, 10));
        const hashedCodes = await Promise.all(backupCodes.map(c => bcrypt.hash(c, 10)));
        db.prepare('UPDATE users SET secret_2fa = ?, is_2fa_active = 1, backup_codes = ? WHERE id = ?')
          .run(secret, JSON.stringify(hashedCodes), req.session.userId);
        delete req.session.tempSecret;
        logger.info(`A2F ACTIVÉE: ${req.session.email}`);
        res.json({ success: true, backupCodes });
    } else {
        res.json({ success: false, message: 'Code incorrect' });
    }
});

app.post('/api/logout', (req, res) => {
    if(req.session.email) logger.info(`DECONNEXION: ${req.session.email}`);
    req.session.destroy();
    res.clearCookie('sessionId');
    res.json({ success: true });
});

// Démarrage HTTPS
const httpsOptions = {
    key: fs.readFileSync('./certs/server.key'),
    cert: fs.readFileSync('./certs/server.cert')
};
https.createServer(httpsOptions, app).listen(3000, () => {
    console.log('🔒 Serveur HTTPS (Avec Audit & Lockout) prêt : https://localhost:3000');
});