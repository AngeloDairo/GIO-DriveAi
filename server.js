'use strict';

const http = require('node:http');
const { randomBytes, scrypt, timingSafeEqual, createHash } = require('node:crypto');
const { promisify } = require('node:util');
const path = require('node:path');
const fs = require('node:fs');
const { DatabaseSync } = require('node:sqlite');

const scryptAsync = promisify(scrypt);
const ROOT = __dirname;

function loadLocalEnvironment() {
    const envPath = path.join(ROOT, '.env');
    if (!fs.existsSync(envPath)) return;
    const contents = fs.readFileSync(envPath, 'utf8').replace(/^\uFEFF/, '');
    for (const [index, rawLine] of contents.split(/\r?\n/).entries()) {
        const line = rawLine.trim();
        if (!line || line.startsWith('#')) continue;
        const separator = line.indexOf('=');
        if (separator < 1) {
            console.warn(`Ignoring malformed .env entry on line ${index + 1}.`);
            continue;
        }
        const name = line.slice(0, separator).trim();
        if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) continue;
        const environmentName = ['GEMINI_API_KEY', 'GEMINI_MODEL'].includes(name.toUpperCase())
            ? name.toUpperCase()
            : name;
        if (process.env[environmentName] !== undefined) continue;
        let value = line.slice(separator + 1).trim();
        if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
            value = value.slice(1, -1);
        } else {
            value = value.replace(/\s+#.*$/, '').trim();
        }
        process.env[environmentName] = value;
    }
}

loadLocalEnvironment();

const PORT = Number(process.env.PORT || 3000);
const IS_PRODUCTION = process.env.NODE_ENV === 'production';
const SESSION_COOKIE = 'gio_session';
const SESSION_TTL_SECONDS = 60 * 60 * 24 * 7;
const RESET_TTL_SECONDS = 60 * 5;
const MAX_BODY_BYTES = 32 * 1024;
const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
const GEMINI_MODEL = process.env.GEMINI_MODEL || 'gemini-flash-lite-latest';
const db = new DatabaseSync(path.join(ROOT, 'gio-driveai.sqlite'));

db.exec(`
    PRAGMA foreign_keys = ON;
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT NOT NULL COLLATE NOCASE UNIQUE,
        email TEXT NOT NULL COLLATE NOCASE UNIQUE,
        password_hash TEXT NOT NULL,
        password_salt TEXT NOT NULL,
        created_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS sessions (
        token_hash TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        expires_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS password_resets (
        email TEXT PRIMARY KEY COLLATE NOCASE,
        code_hash TEXT NOT NULL,
        expires_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS vehicle_pairings (
        code TEXT PRIMARY KEY,
        expires_at INTEGER NOT NULL,
        used_at INTEGER
    );
`);

const loginAttempts = new Map();
const assistantAttempts = new Map();

function json(response, status, payload, headers = {}) {
    response.writeHead(status, {
        'Content-Type': 'application/json; charset=utf-8',
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff',
        ...headers
    });
    response.end(JSON.stringify(payload));
}

function hash(value) {
    return createHash('sha256').update(value).digest('hex');
}

function parseCookies(header = '') {
    return Object.fromEntries(header.split(';').map((part) => {
        const separator = part.indexOf('=');
        if (separator < 0) return ['', ''];
        return [part.slice(0, separator).trim(), decodeURIComponent(part.slice(separator + 1).trim())];
    }).filter(([key]) => key));
}

function cookieHeader(value, maxAge) {
    const secure = IS_PRODUCTION ? '; Secure' : '';
    return `${SESSION_COOKIE}=${encodeURIComponent(value)}; HttpOnly; Path=/; SameSite=Strict; Max-Age=${maxAge}${secure}`;
}

function requireText(value, min, max) {
    return typeof value === 'string' && value.trim().length >= min && value.length <= max;
}

function validEmail(email) {
    return typeof email === 'string' && email.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

async function readJson(request) {
    const chunks = [];
    let size = 0;
    for await (const chunk of request) {
        size += chunk.length;
        if (size > MAX_BODY_BYTES) throw Object.assign(new Error('Request body is too large.'), { status: 413 });
        chunks.push(chunk);
    }
    try {
        return JSON.parse(Buffer.concat(chunks).toString('utf8'));
    } catch {
        throw Object.assign(new Error('Request body must be valid JSON.'), { status: 400 });
    }
}

function publicUser(user) {
    return { id: user.id, username: user.username, email: user.email };
}

function currentUser(request) {
    const token = parseCookies(request.headers.cookie)[SESSION_COOKIE];
    if (!token) return null;
    const user = db.prepare(`
        SELECT users.id, users.username, users.email
        FROM sessions JOIN users ON users.id = sessions.user_id
        WHERE sessions.token_hash = ? AND sessions.expires_at > ?
    `).get(hash(token), Date.now());
    return user || null;
}

function issueSession(userId) {
    const token = randomBytes(32).toString('hex');
    const expiresAt = Date.now() + SESSION_TTL_SECONDS * 1000;
    db.prepare('INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)')
        .run(hash(token), userId, expiresAt);
    return token;
}

function loginIsLimited(ip) {
    const now = Date.now();
    const attempt = loginAttempts.get(ip);
    if (!attempt || attempt.resetAt <= now) {
        loginAttempts.set(ip, { count: 0, resetAt: now + 15 * 60 * 1000 });
        return false;
    }
    return attempt.count >= 10;
}

function recordLoginFailure(ip) {
    const attempt = loginAttempts.get(ip);
    if (attempt) attempt.count += 1;
}

function clearLoginFailures(ip) {
    loginAttempts.delete(ip);
}

function localAssistantReply(messages) {
    const question = messages[messages.length - 1].parts[0].text.toLowerCase();
    if (/\b(hello|hi|hey|good morning|good afternoon|good evening)\b/.test(question)) {
        return 'Hello! I’m GIO DriveAI. I can help with driver safety, basic vehicle maintenance, and troubleshooting. What would you like help with?';
    }
    if (/\b(help|what can you do|how can you help|capabilities)\b/.test(question)) {
        return 'I can share general guidance about safe driving, routine vehicle care, and common warning signs. I can’t see your vehicle data or provide live maps, traffic, weather, or emergency services.';
    }
    if (/\b(emergency|crash|accident|hurt|injur|fire|smoke|danger|stranded)\b/.test(question)) {
        return 'If anyone is in immediate danger, call your local emergency services now. Move to a safe place away from traffic if you can, turn on your hazard lights, and don’t use chat while driving.';
    }
    if (/\b(brake|brakes|tyre|tyres|tire|tires|oil|battery|engine|overheat|overheating|warning light|maintenance|service|fuel|flat)\b/.test(question)) {
        return 'For vehicle concerns, park somewhere safe before checking anything. Don’t continue driving if the brakes feel abnormal, the engine is overheating, or a red warning light is on; consult your owner’s manual and roadside assistance or a qualified mechanic. Tell me the warning light or symptom and your vehicle model for more specific general guidance.';
    }
    if (/\b(direction|directions|route|traffic|weather|location|near me|gps|navigate)\b/.test(question)) {
        return 'I don’t have access to live GPS, maps, traffic, or weather in this app. Please use your vehicle’s navigation or a trusted maps app while parked, or ask a passenger to help.';
    }
    if (/\b(thank you|thanks|thx)\b/.test(question)) {
        return 'You’re welcome! If you have another driving-safety or vehicle-care question, I’m here to help.';
    }
    if (/\b(who are you|your name|gio driveai)\b/.test(question)) {
        return 'I’m GIO DriveAI, your driver-safety and basic vehicle-care assistant. I’m using the built-in offline response mode right now, so I can’t look up live information.';
    }
    const previousUserMessage = messages.slice(0, -1).reverse().find((message) => message.role === 'user');
    const context = previousUserMessage
        ? ` I see your earlier question was “${previousUserMessage.parts[0].text.slice(0, 160)}.”`
        : '';
    return `I’m here to help, but my Gemini connection isn’t configured right now, so I can only answer common driver-safety and vehicle-care questions.${context} Try asking about a vehicle warning light, routine maintenance, or a safe-driving situation.`;
}

function localAssistantResult(messages, fallback = false, providerError = '') {
    const reply = localAssistantReply(messages);
    return {
        reply: fallback
            ? `Gemini${providerError ? ` returned ${providerError}` : ' is unavailable'}. The local assistant answered instead. ${reply}`
            : reply,
        provider: 'local'
    };
}

function safeProviderMessage(message) {
    if (typeof message !== 'string') return '';
    const withoutKey = GEMINI_API_KEY
        ? message.replaceAll(GEMINI_API_KEY, '[redacted]')
        : message;
    return withoutKey
        .replace(/\b(?:AIza|AQ\.)[A-Za-z0-9._-]{20,}/g, '[redacted]')
        .replace(/[\r\n\t]+/g, ' ')
        .slice(0, 180);
}

function passwordMatches(password, salt, expectedHex) {
    return scryptAsync(password, Buffer.from(salt, 'hex'), 64).then((derived) => {
        const expected = Buffer.from(expectedHex, 'hex');
        return expected.length === derived.length && timingSafeEqual(expected, derived);
    });
}

async function createPassword(password) {
    const salt = randomBytes(16);
    const derived = await scryptAsync(password, salt, 64);
    return { salt: salt.toString('hex'), passwordHash: derived.toString('hex') };
}

async function handleApi(request, response, url) {
    if (request.method === 'GET' && url.pathname === '/api/health') {
        return json(response, 200, {
            status: 'online',
            assistantAvailable: true,
            assistantConfigured: Boolean(GEMINI_API_KEY)
        });
    }

    if (request.method === 'GET' && url.pathname === '/api/assistant/status') {
        if (!currentUser(request)) return json(response, 401, { error: 'Sign in to use GIO DriveAI.' });
        return json(response, 200, {
            configured: Boolean(GEMINI_API_KEY),
            available: true,
            provider: GEMINI_API_KEY ? 'gemini' : 'local',
            model: GEMINI_MODEL
        });
    }

    if (request.method === 'GET' && url.pathname === '/api/auth/me') {
        return json(response, 200, { user: currentUser(request) });
    }

    if (request.method !== 'POST') {
        return json(response, 405, { error: 'Method not allowed.' }, { Allow: 'GET, POST' });
    }
    const body = await readJson(request);

    if (url.pathname === '/api/assistant/chat') {
        const user = currentUser(request);
        if (!user) return json(response, 401, { error: 'Sign in to use GIO DriveAI.' });
        if (!Array.isArray(body.messages) || body.messages.length < 1 || body.messages.length > 12) {
            return json(response, 400, { error: 'Send between 1 and 12 recent messages.' });
        }
        const messages = body.messages.map((message) => {
            if (!message || !['user', 'model'].includes(message.role) || !requireText(message.text, 1, 2000)) {
                return null;
            }
            return { role: message.role, parts: [{ text: message.text.trim() }] };
        });
        if (messages.some((message) => message === null) || messages[messages.length - 1].role !== 'user') {
            return json(response, 400, { error: 'Messages must contain text and end with a user message.' });
        }
        const now = Date.now();
        const limit = assistantAttempts.get(user.id);
        if (limit && limit.resetAt > now && limit.count >= 20) {
            return json(response, 429, { error: 'Assistant message limit reached. Try again in a minute.' });
        }
        if (!limit || limit.resetAt <= now) {
            assistantAttempts.set(user.id, { count: 1, resetAt: now + 60 * 1000 });
        } else {
            limit.count += 1;
        }
        if (!GEMINI_API_KEY) {
            return json(response, 200, localAssistantResult(messages));
        }

        let geminiResponse;
        try {
            geminiResponse = await fetch(
                `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(GEMINI_MODEL)}:generateContent`,
                {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'x-goog-api-key': GEMINI_API_KEY
                    },
                    signal: AbortSignal.timeout(20000),
                    body: JSON.stringify({
                        systemInstruction: {
                            parts: [{
                                text: 'You are GIO DriveAI, a helpful vehicle and driver assistant. Be clear and concise. Do not imply access to live vehicle telemetry or emergency services. Never encourage using chat while driving; tell the user to pull over safely first.'
                            }]
                        },
                        contents: messages,
                        generationConfig: { maxOutputTokens: 700, temperature: 0.6 }
                    })
                }
            );
        } catch (error) {
            console.error('Gemini request failed:', error.name);
            return json(response, 200, localAssistantResult(messages, true));
        }
        let geminiData;
        try {
            geminiData = await geminiResponse.json();
        } catch {
            console.error('Gemini returned an invalid JSON response.');
            return json(response, 200, localAssistantResult(messages, true));
        }
        if (!geminiResponse.ok) {
            const providerStatus = typeof geminiData.error?.status === 'string'
                ? geminiData.error.status.replace(/[^A-Z0-9_]/gi, '').slice(0, 40)
                : '';
            const providerMessage = safeProviderMessage(geminiData.error?.message);
            const providerError = `${geminiResponse.status}${providerStatus ? ` ${providerStatus}` : ''}${providerMessage ? `: ${providerMessage}` : ''}`;
            console.error(`Gemini request rejected: HTTP ${geminiResponse.status}${providerStatus ? ` ${providerStatus}` : ''}.`);
            return json(response, 200, localAssistantResult(messages, true, providerError));
        }
        const reply = geminiData.candidates?.[0]?.content?.parts
            ?.map((part) => part.text || '')
            .join('')
            .trim();
        if (!reply) {
            return json(response, 200, localAssistantResult(messages, true));
        }
        return json(response, 200, { reply, provider: 'gemini', model: GEMINI_MODEL });
    }

    if (url.pathname === '/api/auth/register') {
        const username = typeof body.username === 'string' ? body.username.trim() : '';
        const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
        const password = body.password;
        if (!/^[a-zA-Z0-9_.-]+(?: [a-zA-Z0-9_.-]+)*$/.test(username) || username.length < 3 || username.length > 32) {
            return json(response, 400, { error: 'Username must be 3–32 characters and may contain letters, numbers, spaces, dots, underscores or hyphens.' });
        }
        if (!validEmail(email)) return json(response, 400, { error: 'Enter a valid email address.' });
        if (!requireText(password, 9, 128)) {
            return json(response, 400, { error: 'Password must be between 9 and 128 characters.' });
        }
        const credentials = await createPassword(password);
        try {
            const result = db.prepare(`
                INSERT INTO users (username, email, password_hash, password_salt, created_at)
                VALUES (?, ?, ?, ?, ?)
            `).run(username, email, credentials.passwordHash, credentials.salt, Date.now());
            const user = { id: Number(result.lastInsertRowid), username, email };
            const token = issueSession(user.id);
            return json(response, 201, { user }, { 'Set-Cookie': cookieHeader(token, SESSION_TTL_SECONDS) });
        } catch (error) {
            if (String(error.message).includes('UNIQUE constraint failed')) {
                return json(response, 409, { error: 'That username or email is already registered.' });
            }
            throw error;
        }
    }

    if (url.pathname === '/api/auth/login') {
        const ip = request.socket.remoteAddress || 'unknown';
        if (loginIsLimited(ip)) return json(response, 429, { error: 'Too many sign-in attempts. Try again in 15 minutes.' });
        const username = typeof body.username === 'string' ? body.username.trim() : '';
        const password = body.password;
        const user = requireText(username, 1, 254) && typeof password === 'string'
            ? db.prepare('SELECT id, username, email, password_hash, password_salt FROM users WHERE username = ? COLLATE NOCASE OR email = ? COLLATE NOCASE').get(username, username)
            : null;
        const valid = user ? await passwordMatches(password, user.password_salt, user.password_hash) : false;
        if (!valid) {
            recordLoginFailure(ip);
            return json(response, 401, { error: 'Username/email or password is incorrect.' });
        }
        clearLoginFailures(ip);
        db.prepare('DELETE FROM sessions WHERE expires_at <= ?').run(Date.now());
        const token = issueSession(user.id);
        return json(response, 200, { user: publicUser(user) }, { 'Set-Cookie': cookieHeader(token, SESSION_TTL_SECONDS) });
    }

    if (url.pathname === '/api/auth/logout') {
        const token = parseCookies(request.headers.cookie)[SESSION_COOKIE];
        if (token) db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(hash(token));
        return json(response, 200, { ok: true }, { 'Set-Cookie': cookieHeader('', 0) });
    }

    if (url.pathname === '/api/auth/forgot-password') {
        const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
        if (!validEmail(email)) return json(response, 400, { error: 'Enter a valid email address.' });
        const user = db.prepare('SELECT id FROM users WHERE email = ? COLLATE NOCASE').get(email);
        if (!user) return json(response, 200, { message: 'If an account exists for that email, recovery instructions will be sent.' });
        if (IS_PRODUCTION) {
            return json(response, 503, { error: 'Password recovery email delivery is not configured on this server.' });
        }
        const code = randomBytes(12).toString('hex');
        db.prepare('INSERT OR REPLACE INTO password_resets (email, code_hash, expires_at) VALUES (?, ?, ?)')
            .run(email, hash(code), Date.now() + RESET_TTL_SECONDS * 1000);
        return json(response, 200, {
            message: 'Local development recovery code generated. It expires in 5 minutes.',
            resetCode: code
        });
    }

    if (url.pathname === '/api/auth/reset-password') {
        const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
        const code = body.code;
        const password = body.password;
        if (!validEmail(email) || !requireText(code, 1, 64) || !requireText(password, 9, 128)) {
            return json(response, 400, { error: 'Provide a valid email, recovery code and a password of at least 9 characters.' });
        }
        const reset = db.prepare('SELECT code_hash, expires_at FROM password_resets WHERE email = ? COLLATE NOCASE').get(email);
        if (!reset || reset.expires_at <= Date.now() || hash(code.trim()) !== reset.code_hash) {
            return json(response, 400, { error: 'Recovery code is invalid or expired. Request a new one.' });
        }
        const credentials = await createPassword(password);
        db.prepare('UPDATE users SET password_hash = ?, password_salt = ? WHERE email = ? COLLATE NOCASE')
            .run(credentials.passwordHash, credentials.salt, email);
        db.prepare('DELETE FROM password_resets WHERE email = ? COLLATE NOCASE').run(email);
        db.prepare('DELETE FROM sessions WHERE user_id = (SELECT id FROM users WHERE email = ? COLLATE NOCASE)').run(email);
        return json(response, 200, { ok: true });
    }

    if (url.pathname === '/api/vehicle/pairing') {
        const code = randomBytes(4).toString('hex').toUpperCase();
        db.prepare('DELETE FROM vehicle_pairings WHERE expires_at <= ? OR used_at IS NOT NULL').run(Date.now());
        db.prepare('INSERT INTO vehicle_pairings (code, expires_at) VALUES (?, ?)').run(code, Date.now() + RESET_TTL_SECONDS * 1000);
        return json(response, 201, { code, expiresInSeconds: RESET_TTL_SECONDS });
    }

    return json(response, 404, { error: 'API endpoint not found.' });
}

function serveStatic(request, response, url) {
    let pathname;
    try {
        pathname = decodeURIComponent(url.pathname);
    } catch {
        return json(response, 400, { error: 'Invalid URL path.' });
    }
    if (pathname === '/') pathname = '/index.html';
    const filePath = path.resolve(ROOT, `.${pathname}`);
    if (!filePath.startsWith(`${ROOT}${path.sep}`) || !fs.existsSync(filePath) || !fs.statSync(filePath).isFile()) {
        response.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
        return response.end('Not found');
    }
    const extension = path.extname(filePath).toLowerCase();
    const contentType = extension === '.html' ? 'text/html; charset=utf-8'
        : extension === '.css' ? 'text/css; charset=utf-8'
            : extension === '.js' ? 'text/javascript; charset=utf-8'
                : extension === '.svg' ? 'image/svg+xml'
                    : 'application/octet-stream';
    response.writeHead(200, {
        'Content-Type': contentType,
        'X-Content-Type-Options': 'nosniff',
        'Content-Security-Policy': "default-src 'self' https://cdn.tailwindcss.com https://cdnjs.cloudflare.com https://fonts.googleapis.com https://fonts.gstatic.com; style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com; script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; img-src 'self' data:; connect-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'",
        'Referrer-Policy': 'strict-origin-when-cross-origin'
    });
    fs.createReadStream(filePath).pipe(response);
}

const server = http.createServer(async (request, response) => {
    const url = new URL(request.url, `http://${request.headers.host || 'localhost'}`);
    try {
        if (url.pathname.startsWith('/api/')) {
            await handleApi(request, response, url);
        } else if (request.method === 'GET' || request.method === 'HEAD') {
            serveStatic(request, response, url);
        } else {
            json(response, 405, { error: 'Method not allowed.' }, { Allow: 'GET, HEAD' });
        }
    } catch (error) {
        console.error('Request failed:', error);
        if (!response.headersSent) json(response, error.status || 500, { error: error.status ? error.message : 'An internal server error occurred.' });
        else response.destroy();
    }
});

server.listen(PORT, () => {
    console.log(`GIO DriveAI is running at http://localhost:${PORT}`);
    if (IS_PRODUCTION) console.log('Production mode enabled; HTTPS is required for secure session cookies.');
});

function shutdown() {
    server.close(() => {
        db.close();
        process.exit(0);
    });
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
