'use strict';

// ── Константы ──────────────────────────────────────────────────────────────
const DEFAULT_API_BASE = 'http://localhost:8787/api/v1';
const AI_CHECK_DELAY   = 60 * 1000;   // 1 минута
const BYPASS_TTL       = 5 * 60 * 1000;
const CACHE_TTL        = 10 * 60 * 1000;

const CheckLevel = Object.freeze({ FAST: 'fast', AI: 'ai', AI_CONTENT: 'ai_content' });
const CheckStatus = Object.freeze({
    NOT_CHECKED: 'not_checked',
    CHECKING:    'checking',
    SAFE:        'safe',
    PHISHING:    'phishing',
    UNKNOWN:     'unknown',
});

// ── Состояние ──────────────────────────────────────────────────────────────
const urlCache         = new Map();
const manualBypassCache = new Map();
const pendingChecks    = new Map();

let settings = {
    apiUrl:          DEFAULT_API_BASE.replace('/api/v1', ''),
    apiKey:          '',
    sensitivity:     65,
    checkMode:       'auto',
    notifEnabled:    true,
    linkWarning:     true,
    plan:            'free',
};

let checkCounter = { today: 0, week: 0, total: 0, blocked: 0, safe: 0, unknown: 0 };

function getApiBase() {
    return (settings.apiUrl || '').replace(/\/$/, '') + '/api/v1';
}

function getThreshold() {
    return (settings.sensitivity || 65) / 100;
}

function buildHeaders() {
    const h = { 'Content-Type': 'application/json' };
    if (settings.apiKey) h['X-API-Key'] = settings.apiKey;
    return h;
}

// ── Загрузка настроек ──────────────────────────────────────────────────────
async function loadSettings() {
    try {
        const data = await chrome.storage.sync.get({
            apiUrl:       'http://localhost:8787',
            apiKey:       '',
            sensitivity:  65,
            checkMode:    'auto',
            notifEnabled: true,
            linkWarning:  true,
            plan:         'free',
        });
        settings = data;
    } catch (err) {
        console.warn('АнтиФиш: не удалось загрузить настройки:', err);
    }
}

chrome.storage.onChanged.addListener((changes, area) => {
    if (area !== 'sync') return;
    for (const [key, { newValue }] of Object.entries(changes)) {
        if (key in settings) settings[key] = newValue;
    }
});

// ── Статистика ─────────────────────────────────────────────────────────────
function getTodayKey() {
    const d = new Date();
    return `${d.getFullYear()}-${d.getMonth() + 1}-${d.getDate()}`;
}

function getWeekKey() {
    const d = new Date();
    const s = new Date(d);
    s.setDate(d.getDate() - d.getDay());
    return `${s.getFullYear()}-${s.getMonth() + 1}-${s.getDate()}`;
}

function updateCheckStats(result) {
    const todayKey = getTodayKey();
    const weekKey  = getWeekKey();

    checkCounter.total++;
    if (result.phishing === true)  checkCounter.blocked++;
    else if (result.phishing === false) checkCounter.safe++;
    else checkCounter.unknown++;

    chrome.storage.local.get(['daily_stats', 'weekly_stats'], data => {
        const daily  = data.daily_stats  || {};
        const weekly = data.weekly_stats || {};

        daily[todayKey]  = daily[todayKey]  || { checks: 0, blocked: 0 };
        weekly[weekKey]  = weekly[weekKey]  || { checks: 0, blocked: 0 };

        daily[todayKey].checks++;
        weekly[weekKey].checks++;

        if (result.phishing === true) {
            daily[todayKey].blocked++;
            weekly[weekKey].blocked++;
        }

        chrome.storage.local.set({
            daily_stats:   daily,
            weekly_stats:  weekly,
            stats_today:   daily[todayKey].checks,
            stats_week:    weekly[weekKey].checks,
            stats_blocked: checkCounter.blocked,
            stats_total:   checkCounter.total,
            stats_safe:    checkCounter.safe,
        });
    });
}

async function loadInitialStats() {
    try {
        const data = await chrome.storage.local.get([
            'stats_today', 'stats_week', 'stats_blocked', 'stats_total', 'stats_safe'
        ]);
        checkCounter.today   = data.stats_today   || 0;
        checkCounter.week    = data.stats_week    || 0;
        checkCounter.blocked = data.stats_blocked || 0;
        checkCounter.total   = data.stats_total   || 0;
        checkCounter.safe    = data.stats_safe    || 0;
    } catch (err) {
        console.error('АнтиФиш: ошибка загрузки статистики:', err);
    }
}

// ── Основная логика проверки ───────────────────────────────────────────────
async function checkUrl(url, level = CheckLevel.FAST, content = null) {
    const cacheKey = `${url}:${level}`;
    const cached = urlCache.get(cacheKey);
    if (cached) return cached.result;

    const base = getApiBase();
    let endpoint, body;

    switch (level) {
        case CheckLevel.FAST:
            endpoint = `${base}/fast`;
            body = { link: url, threshold: getThreshold() };
            break;
        case CheckLevel.AI:
            endpoint = `${base}/ai`;
            body = { link: url, threshold: getThreshold() };
            break;
        case CheckLevel.AI_CONTENT:
            endpoint = `${base}/ai-content`;
            body = { link: url, content: content || '', threshold: getThreshold() };
            break;
    }

    try {
        const resp = await fetch(endpoint, {
            method:  'POST',
            headers: buildHeaders(),
            body:    JSON.stringify(body),
        });

        if (!resp.ok) {
            console.warn(`АнтиФиш: API ${level} вернул ${resp.status}`);
            return null;
        }

        const result = await resp.json();

        urlCache.set(cacheKey, { result, timestamp: Date.now(), level });
        return result;
    } catch (err) {
        console.error(`АнтиФиш: ошибка запроса (${level}):`, err.message);
        return null;
    }
}

async function extractPageContent(tabId) {
    return new Promise(resolve => {
        chrome.tabs.sendMessage(tabId, { type: 'GET_PAGE_CONTENT' }, resp => {
            if (chrome.runtime.lastError || !resp?.content) {
                resolve('');
            } else {
                resolve(resp.content.substring(0, 5000));
            }
        });
    });
}

async function checkUrlThreeStep(url, tabId) {
    // Ручной bypass
    const bypass = manualBypassCache.get(`bypass:${url}`);
    if (bypass && Date.now() - bypass.timestamp < BYPASS_TTL) {
        return { status: CheckStatus.SAFE, result: { phishing: false, source: 'manual_bypass' } };
    }

    // Шаг 1: быстрая проверка
    const fastResult = await checkUrl(url, CheckLevel.FAST);
    if (!fastResult) return { status: CheckStatus.UNKNOWN, result: null };

    if (fastResult.phishing === true) {
        updateCheckStats(fastResult);
        return { status: CheckStatus.PHISHING, result: fastResult, level: CheckLevel.FAST };
    }
    if (fastResult.phishing === false) {
        updateCheckStats(fastResult);
        return { status: CheckStatus.SAFE, result: fastResult, level: CheckLevel.FAST };
    }

    // Шаг 2: AI-проверка по URL
    const aiResult = await checkUrl(url, CheckLevel.AI);
    if (!aiResult) {
        updateCheckStats(fastResult);
        return { status: CheckStatus.UNKNOWN, result: fastResult };
    }

    if (aiResult.phishing === true) {
        updateCheckStats(aiResult);
        return { status: CheckStatus.PHISHING, result: aiResult, level: CheckLevel.AI };
    }
    if (aiResult.phishing === false) {
        updateCheckStats(aiResult);
        return { status: CheckStatus.SAFE, result: aiResult, level: CheckLevel.AI };
    }

    // Шаг 3: AI-анализ контента (только Премиум)
    updateCheckStats(aiResult);
    if (settings.plan === 'premium') {
        scheduleContentCheck(url, tabId);
    }
    return { status: CheckStatus.UNKNOWN, result: aiResult, level: CheckLevel.AI };
}

function scheduleContentCheck(url, tabId) {
    const key = `${url}:${tabId}`;
    if (pendingChecks.has(key)) return;

    const timeoutId = setTimeout(async () => {
        try {
            const content = await extractPageContent(tabId);
            const result  = await checkUrl(url, CheckLevel.AI_CONTENT, content);
            if (!result) return;

            updateCheckStats(result);

            if (result.phishing === true) {
                chrome.tabs.update(tabId, {
                    url: chrome.runtime.getURL('blocked.html') +
                         `?url=${encodeURIComponent(url)}&source=${result.source || 'ai_content'}&risk=Высокий`,
                });
                _showNotification('⚠️ Фишинг обнаружен', 'Страница заблокирована после анализа содержимого');
            }
        } catch (err) {
            console.error('АнтиФиш: ошибка AI-CONTENT проверки:', err);
        } finally {
            pendingChecks.delete(key);
        }
    }, AI_CHECK_DELAY);

    pendingChecks.set(key, { url, tabId, timeoutId, scheduledAt: Date.now() });
}

function _showNotification(title, message) {
    if (!settings.notifEnabled) return;
    chrome.notifications.create({
        type: 'basic', iconUrl: 'icons/icon48.png', title, message,
    }).catch(() => {});
}

function addManualBypass(url) {
    const key = `bypass:${url}`;
    manualBypassCache.set(key, { url, timestamp: Date.now() });
    setTimeout(() => manualBypassCache.delete(key), BYPASS_TTL);
}

function removeFromCache(url) {
    for (const key of urlCache.keys()) {
        if (key.startsWith(`${url}:`)) urlCache.delete(key);
    }
    for (const [key, check] of pendingChecks.entries()) {
        if (check.url === url) {
            clearTimeout(check.timeoutId);
            pendingChecks.delete(key);
        }
    }
}

// ── Слушатели вкладок ──────────────────────────────────────────────────────
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
    if (changeInfo.status !== 'loading' || !tab.url) return;

    const url = tab.url;
    if (url.startsWith('chrome://') || url.startsWith('chrome-extension://') || url.startsWith('about:')) return;

    if (settings.checkMode === 'manual') return;

    const checkResult = await checkUrlThreeStep(url, tabId);

    if (checkResult.status === CheckStatus.PHISHING) {
        const r = checkResult.result || {};
        const chance = r.chance ?? '';
        chrome.tabs.update(tabId, {
            url: chrome.runtime.getURL('blocked.html') +
                 `?url=${encodeURIComponent(url)}&source=${r.source || 'unknown'}&risk=${chance ? 'Высокий' : 'Средний'}`,
        });
        _showNotification('⚠️ Фишинг-сайт заблокирован', 'Доступ к сайту ограничен системой безопасности АнтиФиш');
    }
});

chrome.tabs.onRemoved.addListener(tabId => {
    for (const [key, check] of pendingChecks.entries()) {
        if (check.tabId === tabId) {
            clearTimeout(check.timeoutId);
            pendingChecks.delete(key);
        }
    }
});

// ── Обмен сообщениями с попапом и страницами ───────────────────────────────
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    switch (request.type) {

        case 'GET_CHECK_STATUS': {
            const levels = [CheckLevel.AI, CheckLevel.FAST, CheckLevel.AI_CONTENT];
            for (const lvl of levels) {
                const c = urlCache.get(`${request.url}:${lvl}`);
                if (c) {
                    sendResponse({ checked: true, result: c.result, level: c.level, timestamp: c.timestamp });
                    return true;
                }
            }
            sendResponse({ checked: false });
            return true;
        }

        case 'CLEAR_CACHE':
            urlCache.clear();
            manualBypassCache.clear();
            pendingChecks.forEach(c => clearTimeout(c.timeoutId));
            pendingChecks.clear();
            sendResponse({ success: true });
            return true;

        case 'ADD_MANUAL_BYPASS':
            addManualBypass(request.url);
            sendResponse({ success: true });
            return true;

        case 'REMOVE_FROM_CACHE':
            removeFromCache(request.url);
            sendResponse({ success: true });
            return true;

        case 'GET_STATS': {
            const todayKey = getTodayKey();
            const weekKey  = getWeekKey();
            chrome.storage.local.get(['daily_stats', 'weekly_stats'], data => {
                const daily  = data.daily_stats  || {};
                const weekly = data.weekly_stats || {};
                sendResponse({
                    success: true,
                    today:   daily[todayKey]?.checks  || 0,
                    week:    weekly[weekKey]?.checks  || 0,
                    blocked: checkCounter.blocked,
                    total:   checkCounter.total,
                    safe:    checkCounter.safe,
                    unknown: checkCounter.unknown,
                });
            });
            return true;
        }

        case 'UPDATE_STATS':
            if (request.result) updateCheckStats(request.result);
            sendResponse({ success: true });
            return true;

        case 'RESET_STATS':
            checkCounter = { today: 0, week: 0, total: 0, blocked: 0, safe: 0, unknown: 0 };
            chrome.storage.local.clear(() => sendResponse({ success: true }));
            return true;

        case 'GET_SETTINGS':
            sendResponse({ success: true, settings });
            return true;

        case 'PLAN_CHANGED':
            settings.plan = request.plan || 'free';
            sendResponse({ success: true });
            return true;

        case 'CHECK_LINK': {
            // Мгновенная проверка ссылки из content.js
            checkUrl(request.url, CheckLevel.FAST)
                .then(result => {
                    if (result?.phishing === true) {
                        sendResponse({ block: true, data: result });
                    } else {
                        sendResponse({ block: false });
                    }
                })
                .catch(() => sendResponse({ block: false }));
            return true;
        }
    }

    return true;
});

// ── Очистка кэша по TTL ────────────────────────────────────────────────────
setInterval(() => {
    const now = Date.now();
    for (const [key, data] of urlCache.entries()) {
        if (now - data.timestamp > CACHE_TTL) urlCache.delete(key);
    }
}, 5 * 60 * 1000);

// ── Проверка лицензии ──────────────────────────────────────────────────────
async function verifyLicense() {
    const data = await chrome.storage.sync.get(['licenseKey', 'plan']);
    const licenseKey = data.licenseKey || '';
    const currentPlan = data.plan || 'free';

    if (!licenseKey || currentPlan !== 'premium') return;

    try {
        const headers = { 'Content-Type': 'application/json' };
        if (settings.apiKey) headers['X-API-Key'] = settings.apiKey;
        const res = await fetch(`${getApiBase()}/license/verify`, {
            method: 'POST',
            headers,
            body: JSON.stringify({ key: licenseKey }),
            signal: AbortSignal.timeout(10000),
        });
        if (!res.ok) return;
        const result = await res.json();

        if (!result.valid) {
            // Лицензия истекла или недействительна — понижаем до бесплатной
            await chrome.storage.sync.set({ plan: 'free' });
            settings.plan = 'free';
            console.warn('АнтиФиш: лицензия истекла или недействительна, переход на бесплатную версию');
            chrome.tabs.create({
                url: chrome.runtime.getURL('license-expired.html') +
                     `?key=${encodeURIComponent(licenseKey)}`,
            });
        } else {
            settings.plan = result.plan || 'premium';
        }
    } catch (err) {
        console.warn('АнтиФиш: не удалось проверить лицензию:', err.message);
    }
}

// ── Запуск ─────────────────────────────────────────────────────────────────
(async () => {
    await loadSettings();
    await loadInitialStats();
    console.log('АнтиФиш v1.1.0 запущен | API:', getApiBase(), '| план:', settings.plan);
    await verifyLicense();
})();

// ── Экспорт для тестов ─────────────────────────────────────────────────────
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { checkUrlThreeStep, removeFromCache, CheckLevel, CheckStatus };
}
