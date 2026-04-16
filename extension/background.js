console.log('Сервис-воркер АнтиФиш запущен');

const API_BASE = 'http://localhost:8787/api/v1';
const urlCache = new Map();
const manualBypassCache = new Map();
const pendingChecks = new Map();
const AI_CHECK_DELAY = 60 * 1000;
const BYPASS_TTL = 5 * 60 * 1000;

const CheckLevel = {
    FAST: 'fast',
    AI: 'ai',
    AI_CONTENT: 'ai_content'
};

const CheckStatus = {
    NOT_CHECKED: 'not_checked',
    CHECKING: 'checking',
    SAFE: 'safe',
    PHISHING: 'phishing',
    UNKNOWN: 'unknown'
};

let checkCounter = {
    today: 0,
    week: 0,
    total: 0,
    blocked: 0,
    safe: 0,
    unknown: 0
};

function getTodayKey() {
    const now = new Date();
    return `${now.getFullYear()}-${now.getMonth() + 1}-${now.getDate()}`;
}

function getWeekKey() {
    const now = new Date();
    const startOfWeek = new Date(now);
    startOfWeek.setDate(now.getDate() - now.getDay());
    return `${startOfWeek.getFullYear()}-${startOfWeek.getMonth() + 1}-${startOfWeek.getDate()}`;
}

function updateCheckStats(result) {
    const todayKey = getTodayKey();
    const weekKey = getWeekKey();
    
    try {
        checkCounter.total++;
        
        if (result.phishing === true) {
            checkCounter.blocked++;
        } else if (result.phishing === false) {
            checkCounter.safe++;
        } else {
            checkCounter.unknown++;
        }
        
        chrome.storage.local.get(['daily_stats', 'weekly_stats'], (data) => {
            const dailyStats = data.daily_stats || {};
            const weeklyStats = data.weekly_stats || {};
            
            if (!dailyStats[todayKey]) {
                dailyStats[todayKey] = { checks: 0, blocked: 0 };
            }
            dailyStats[todayKey].checks++;
            if (result.phishing === true) {
                dailyStats[todayKey].blocked++;
            }
            
            if (!weeklyStats[weekKey]) {
                weeklyStats[weekKey] = { checks: 0, blocked: 0 };
            }
            weeklyStats[weekKey].checks++;
            if (result.phishing === true) {
                weeklyStats[weekKey].blocked++;
            }
            
            chrome.storage.local.set({
                daily_stats: dailyStats,
                weekly_stats: weeklyStats,
                stats_today: dailyStats[todayKey]?.checks || 0,
                stats_week: weeklyStats[weekKey]?.checks || 0,
                stats_blocked: checkCounter.blocked,
                stats_total: checkCounter.total
            });
        });
        
    } catch (error) {
        console.error('Ошибка обновления статистики:', error);
    }
}

async function loadInitialStats() {
    try {
        const data = await chrome.storage.local.get([
            'stats_today', 
            'stats_week', 
            'stats_blocked',
            'stats_total'
        ]);
        
        checkCounter.today = data.stats_today || 0;
        checkCounter.week = data.stats_week || 0;
        checkCounter.blocked = data.stats_blocked || 0;
        checkCounter.total = data.stats_total || 0;
        
        console.log('Статистика загружена:', checkCounter);
    } catch (error) {
        console.error('Ошибка загрузки статистики:', error);
    }
}

loadInitialStats();

async function checkUrl(url, level = CheckLevel.FAST, content = null) {
    console.log(`Проверяем URL (${level}):`, url);
    
    const cacheKey = `${url}:${level}`;
    const cached = urlCache.get(cacheKey);
    if (cached) {
        console.log('Используем кэш для:', cacheKey);
        return cached.result;
    }

    try {
        let endpoint;
        let requestBody;
        
        switch(level) {
            case CheckLevel.FAST:
                endpoint = `${API_BASE}/fast`;
                requestBody = { link: url };
                break;
                
            case CheckLevel.AI:
                endpoint = `${API_BASE}/ai`;
                requestBody = { link: url };
                break;
                
            case CheckLevel.AI_CONTENT:
                endpoint = `${API_BASE}/ai-content`;
                requestBody = { 
                    link: url, 
                    content: content || 'Нет контента для анализа' 
                };
                break;
        }

        const response = await fetch(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(requestBody)
        });

        if (!response.ok) {
            console.error(`Ошибка API (${level}):`, response.status);
            return null;
        }
        
        const result = await response.json();
        console.log(`Результат проверки (${level}):`, result);
        
        urlCache.set(cacheKey, {
            result: result,
            timestamp: Date.now(),
            level: level
        });

        return result;
    } catch (error) {
        console.error(`Ошибка проверки URL (${level}):`, error);
        return null;
    }
}

async function extractPageContent(url, tabId) {
    return new Promise((resolve) => {
        chrome.tabs.sendMessage(
            tabId,
            { type: 'GET_PAGE_CONTENT' },
            (response) => {
                if (chrome.runtime.lastError) {
                    console.log('Не удалось получить контент:', chrome.runtime.lastError.message);
                    resolve('Нет контента для анализа');
                } else if (response && response.content) {
                    const content = response.content.substring(0, 5000);
                    resolve(content);
                } else {
                    resolve('Нет контента для анализа');
                }
            }
        );
    });
}

async function checkUrlThreeStep(url, tabId) {
    console.log('Запуск трехэтапной проверки для:', url);
    
    const bypassKey = `bypass:${url}`;
    const bypassData = manualBypassCache.get(bypassKey);
    
    if (bypassData && (Date.now() - bypassData.timestamp) < BYPASS_TTL) {
        console.log('Сайт был вручную разблокирован пользователем');
        return { 
            status: CheckStatus.SAFE, 
            result: { phishing: false, source: 'manual_bypass' },
            level: 'manual_bypass'
        };
    }
    
    const fastResult = await checkUrl(url, CheckLevel.FAST);
    
    if (!fastResult) {
        console.log('Ошибка при FAST проверке');
        return { status: CheckStatus.UNKNOWN, result: null };
    }
    
    if (fastResult.phishing === true) {
        console.log('Фишинг обнаружен на FAST этапе:', fastResult.source);
        updateCheckStats(fastResult);
        return { 
            status: CheckStatus.PHISHING, 
            result: fastResult,
            level: CheckLevel.FAST 
        };
    }
    
    if (fastResult.phishing === false) {
        console.log('Сайт безопасен (белый список):', fastResult.source);
        updateCheckStats(fastResult);
        return { 
            status: CheckStatus.SAFE, 
            result: fastResult,
            level: CheckLevel.FAST 
        };
    }
    
    if (fastResult.phishing === null || fastResult.phishing === undefined) {
        console.log('FAST: Не в списках, проверяем через AI...');
        
        const aiResult = await checkUrl(url, CheckLevel.AI);
        
        if (!aiResult) {
            console.log('Ошибка при AI проверке');
            updateCheckStats(fastResult);
            return { 
                status: CheckStatus.UNKNOWN, 
                result: fastResult,
                level: CheckLevel.FAST 
            };
        }
        
        if (aiResult.phishing === true) {
            console.log('Фишинг обнаружен AI:', aiResult.source);
            updateCheckStats(aiResult);
            return { 
                status: CheckStatus.PHISHING, 
                result: aiResult,
                level: CheckLevel.AI 
            };
        }
        
        if (aiResult.phishing === false) {
            console.log('AI определил как безопасный:', aiResult.source);
            updateCheckStats(aiResult);
            return { 
                status: CheckStatus.SAFE, 
                result: aiResult,
                level: CheckLevel.AI 
            };
        }
        
        if (aiResult.phishing === null || aiResult.phishing === undefined) {
            console.log('AI не определил, планируем проверку контента...');
            updateCheckStats(aiResult);
            scheduleContentCheck(url, tabId);
            
            return { 
                status: CheckStatus.UNKNOWN, 
                result: aiResult,
                level: CheckLevel.AI 
            };
        }
    }
    
    updateCheckStats(fastResult);
    return { 
        status: CheckStatus.UNKNOWN, 
        result: fastResult,
        level: CheckLevel.FAST 
    };
}

function scheduleContentCheck(url, tabId) {
    const checkKey = `${url}:${tabId}`;
    
    if (pendingChecks.has(checkKey)) {
        console.log('Проверка контента уже запланирована для:', url);
        return;
    }
    
    console.log('Планируем проверку контента через 1 минуту для:', url);
    
    const timeoutId = setTimeout(async () => {
        console.log('Запуск AI-CONTENT проверки для:', url);
        
        try {
            const content = await extractPageContent(url, tabId);
            const contentResult = await checkUrl(url, CheckLevel.AI_CONTENT, content);
            
            if (contentResult) {
                console.log('Результат AI-CONTENT проверки:', contentResult);
                updateCheckStats(contentResult);
                
                if (contentResult.phishing === true) {
                    console.log('Фишинг обнаружен при анализе контента!');
                    
                    chrome.tabs.update(tabId, {
                        url: chrome.runtime.getURL('blocked.html') + 
                             '?url=' + encodeURIComponent(url) +
                             '&source=' + (contentResult.source || 'ai_content') +
                             '&risk=' + (contentResult.chance ? 'Высокий' : 'Средний')
                    });
                    
                    try {
                        await chrome.notifications.create({
                            type: 'basic',
                            iconUrl: 'icons/icon48.png',
                            title: '⚠️ Фишинг обнаружен',
                            message: 'Страница заблокирована после анализа контента'
                        });
                    } catch (e) {
                        console.log('Уведомление не доступно:', e);
                    }
                }
            }
        } catch (error) {
            console.error('Ошибка при проверке контента:', error);
        } finally {
            pendingChecks.delete(checkKey);
        }
    }, AI_CHECK_DELAY);
    
    pendingChecks.set(checkKey, {
        url: url,
        tabId: tabId,
        timeoutId: timeoutId,
        scheduledAt: Date.now()
    });
}

function addManualBypass(url) {
    const bypassKey = `bypass:${url}`;
    manualBypassCache.set(bypassKey, {
        url: url,
        timestamp: Date.now(),
        reason: 'user_manual_override'
    });
    
    console.log('Добавлен ручной bypass для:', url);
    
    setTimeout(() => {
        manualBypassCache.delete(bypassKey);
    }, BYPASS_TTL);
}

function removeFromCache(url) {
    console.log('Удаляем из кэша URL:', url);
    
    for (const [key, data] of urlCache.entries()) {
        if (key.startsWith(`${url}:`)) {
            urlCache.delete(key);
            console.log('Удалено из кэша:', key);
        }
    }
    
    for (const [key, check] of pendingChecks.entries()) {
        if (check.url === url) {
            clearTimeout(check.timeoutId);
            pendingChecks.delete(key);
            console.log('Удалена запланированная проверка для:', url);
        }
    }
}

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
    if (changeInfo.status === 'loading' && tab.url) {
        const url = tab.url;
        
        if (url.startsWith('chrome://') || 
            url.startsWith('chrome-extension://') ||
            url.startsWith('about:')) {
            return;
        }

        console.log('Проверяем страницу:', url);
        
        const checkResult = await checkUrlThreeStep(url, tabId);
        
        if (checkResult.status === CheckStatus.PHISHING) {
            console.log('Блокируем фишинг-сайт:', url);
            
            chrome.tabs.update(tabId, {
                url: chrome.runtime.getURL('blocked.html') + 
                     '?url=' + encodeURIComponent(url) +
                     '&source=' + (checkResult.result?.source || 'unknown') +
                     '&risk=' + (checkResult.result?.chance ? 'Высокий' : 'Средний')
            });
            
            try {
                await chrome.notifications.create({
                    type: 'basic',
                    iconUrl: 'icons/icon48.png',
                    title: '⚠️ Фишинг-сайт заблокирован',
                    message: 'Доступ к сайту ограничен системой безопасности'
                });
            } catch (e) {
                console.log('Уведомление не доступно:', e);
            }
        }
        
        else if (checkResult.status === CheckStatus.SAFE) {
            console.log('Сайт безопасен:', url);
        }
        
        else if (checkResult.status === CheckStatus.UNKNOWN) {
            console.log('Статус неизвестен, AI проверка завершена или запланирована:', url);
        }
    }
});

chrome.tabs.onRemoved.addListener((tabId) => {
    for (const [key, check] of pendingChecks.entries()) {
        if (check.tabId === tabId) {
            clearTimeout(check.timeoutId);
            pendingChecks.delete(key);
            console.log('Удалена запланированная проверка для закрытой вкладки:', check.url);
        }
    }
});

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    switch(request.type) {
        case 'GET_CHECK_STATUS':
            const cacheKey = `${request.url}:fast`;
            const cached = urlCache.get(cacheKey);
            
            if (cached) {
                sendResponse({
                    checked: true,
                    result: cached.result,
                    level: cached.level,
                    timestamp: cached.timestamp
                });
            } else {
                const aiCacheKey = `${request.url}:ai`;
                const aiCached = urlCache.get(aiCacheKey);
                
                if (aiCached) {
                    sendResponse({
                        checked: true,
                        result: aiCached.result,
                        level: aiCached.level,
                        timestamp: aiCached.timestamp
                    });
                } else {
                    sendResponse({ checked: false });
                }
            }
            break;
            
        case 'CLEAR_CACHE':
            urlCache.clear();
            manualBypassCache.clear();
            pendingChecks.forEach(check => clearTimeout(check.timeoutId));
            pendingChecks.clear();
            console.log('Кэш очищен');
            sendResponse({ success: true });
            break;
            
        case 'ADD_MANUAL_BYPASS':
            addManualBypass(request.url);
            sendResponse({ success: true });
            break;
            
        case 'REMOVE_FROM_CACHE':
            removeFromCache(request.url);
            sendResponse({ success: true });
            break;
            
        case 'GET_STATS':
            const todayKey = getTodayKey();
            const weekKey = getWeekKey();
            
            chrome.storage.local.get(['daily_stats', 'weekly_stats'], (data) => {
                const dailyStats = data.daily_stats || {};
                const weeklyStats = data.weekly_stats || {};
                
                const todayChecks = dailyStats[todayKey]?.checks || 0;
                const weekChecks = weeklyStats[weekKey]?.checks || 0;
                
                sendResponse({
                    success: true,
                    today: todayChecks,
                    week: weekChecks,
                    blocked: checkCounter.blocked,
                    total: checkCounter.total,
                    safe: checkCounter.safe,
                    unknown: checkCounter.unknown
                });
            });
            return true;
            
        case 'UPDATE_STATS':
            if (request.result) {
                updateCheckStats(request.result);
                sendResponse({ success: true });
            }
            return true;
            
        case 'RESET_STATS':
            checkCounter = {
                today: 0,
                week: 0,
                total: 0,
                blocked: 0,
                safe: 0,
                unknown: 0
            };
            chrome.storage.local.clear(() => {
                sendResponse({ success: true });
            });
            return true;
    }
    
    return true;
});

setInterval(() => {
    const now = Date.now();
    const CACHE_TTL = 10 * 60 * 1000;
    
    for (const [key, data] of urlCache.entries()) {
        if (now - data.timestamp > CACHE_TTL) {
            urlCache.delete(key);
        }
    }
}, 5 * 60 * 1000);

if (typeof module !== 'undefined' && module.exports) {
    module.exports = { 
        checkUrlThreeStep,
        removeFromCache,
        CheckLevel,
        CheckStatus
    };
}