document.addEventListener('DOMContentLoaded', async () => {
    const currentUrlEl = document.getElementById('currentUrl');
    const siteStatusEl = document.getElementById('siteStatus');
    const currentSiteEl = document.getElementById('currentSite');
    const todayChecksEl = document.getElementById('todayChecks');
    const weekChecksEl = document.getElementById('weekChecks');
    const totalChecksEl = document.getElementById('totalChecks');
    const blockedCountEl = document.getElementById('blockedCount');
    const updateTimeEl = document.getElementById('updateTime');
    
    const checkCurrentPageBtn = document.getElementById('checkCurrentPage');
    const manualCheckBtn = document.getElementById('manualCheck');
    const manualCheckSection = document.getElementById('manualCheckSection');
    const manualUrlInput = document.getElementById('manualUrl');
    const submitCheckBtn = document.getElementById('submitCheck');
    const manualResultEl = document.getElementById('manualResult');
    const detailedStatsBtn = document.getElementById('detailedStats');
    const viewHistoryBtn = document.getElementById('viewHistory');
    const clearCacheBtn = document.getElementById('clearCache');

    let stats = {
        today: 0,
        week: 0,
        total: 0,
        blocked: 0
    };

    async function init() {
        await loadStats();
        await updateCurrentTabInfo();
        updateTime();
        
        setInterval(updateTime, 60000);
        setInterval(updateCurrentTabInfo, 5000);
    }

    async function loadStats() {
        try {
            const response = await new Promise((resolve) => {
                chrome.runtime.sendMessage(
                    { type: 'GET_STATS' },
                    (response) => {
                        if (chrome.runtime.lastError) {
                            console.error('Ошибка:', chrome.runtime.lastError);
                            resolve(null);
                        } else {
                            resolve(response);
                        }
                    }
                );
            });
            
            if (response && response.success) {
                stats.today = response.today || 0;
                stats.week = response.week || 0;
                stats.total = response.total || 0;
                stats.blocked = response.blocked || 0;
                
                todayChecksEl.textContent = stats.today;
                weekChecksEl.textContent = stats.week;
                totalChecksEl.textContent = stats.total;
                blockedCountEl.textContent = stats.blocked;
            }
        } catch (error) {
            console.error('Ошибка загрузки статистики:', error);
        }
    }

    async function updateCurrentTabInfo() {
        try {
            const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
            
            if (tab && tab.url && !tab.url.startsWith('chrome://')) {
                const url = new URL(tab.url);
                currentUrlEl.textContent = url.hostname;
                
                const result = await checkUrlStatus(tab.url);
                updateSiteStatus(result, tab.url);
            } else {
                currentUrlEl.textContent = 'Нет активной вкладки';
                siteStatusEl.innerHTML = '<i class="fas fa-question-circle"></i> Не проверено';
                siteStatusEl.className = 'site-status unknown';
                currentSiteEl.className = 'current-site unknown';
            }
        } catch (error) {
            console.error('Ошибка получения информации:', error);
            currentUrlEl.textContent = 'Ошибка загрузки';
            siteStatusEl.innerHTML = '<i class="fas fa-exclamation-triangle"></i> Ошибка';
            siteStatusEl.className = 'site-status warning';
            currentSiteEl.className = 'current-site warning';
        }
    }

    async function checkUrlStatus(url) {
        return new Promise((resolve) => {
            chrome.runtime.sendMessage(
                { type: 'GET_CHECK_STATUS', url: url },
                (response) => {
                    if (chrome.runtime.lastError) {
                        console.error('Ошибка:', chrome.runtime.lastError);
                        resolve({ checked: false });
                    } else {
                        resolve(response || { checked: false });
                    }
                }
            );
        });
    }

    function updateSiteStatus(result, url) {
        if (!result.checked) {
            siteStatusEl.innerHTML = '<i class="fas fa-question-circle"></i> Не проверено';
            siteStatusEl.className = 'site-status unknown';
            currentSiteEl.className = 'current-site unknown';
            return;
        }

        const status = result.result;
        
        if (status.phishing === true) {
            siteStatusEl.innerHTML = '<i class="fas fa-exclamation-triangle"></i> Опасный';
            siteStatusEl.className = 'site-status danger';
            currentSiteEl.className = 'current-site danger';
            
            if (!url.includes('blocked.html')) {
                loadStats();
            }
        } 
        else if (status.phishing === false) {
            siteStatusEl.innerHTML = '<i class="fas fa-check-circle"></i> Безопасен';
            siteStatusEl.className = 'site-status safe';
            currentSiteEl.className = 'current-site';
        } 
        else {
            siteStatusEl.innerHTML = '<i class="fas fa-search"></i> Проверяется...';
            siteStatusEl.className = 'site-status warning';
            currentSiteEl.className = 'current-site warning';
        }
    }

    function updateTime() {
        const now = new Date();
        updateTimeEl.textContent = now.toLocaleTimeString('ru-RU', { 
            hour: '2-digit', 
            minute: '2-digit' 
        });
    }

    async function manualCheck(url) {
        if (!url) return;
        
        manualResultEl.textContent = 'Проверяем...';
        manualResultEl.className = 'check-result warning show';
        
        try {
            const response = await fetch('http://localhost:8787/api/v1/fast', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ link: url })
            });

            if (!response.ok) throw new Error(`Ошибка HTTP: ${response.status}`);
            
            const result = await response.json();
            
            chrome.runtime.sendMessage({
                type: 'UPDATE_STATS',
                result: result
            }, () => {
                loadStats();
            });

            if (result.phishing === true) {
                manualResultEl.className = 'check-result danger show';
                manualResultEl.innerHTML = `
                    <strong><i class="fas fa-exclamation-triangle"></i> ОПАСНО!</strong>
                    Фишинг обнаружен<br>
                    <small>Источник: ${result.source || 'неизвестно'}</small>
                `;
            } else if (result.phishing === false) {
                manualResultEl.className = 'check-result safe show';
                manualResultEl.innerHTML = `
                    <strong><i class="fas fa-check-circle"></i> БЕЗОПАСНО</strong>
                    Сайт проверен<br>
                    <small>Источник: ${result.source || 'неизвестно'}</small>
                `;
            } else {
                manualResultEl.className = 'check-result warning show';
                manualResultEl.innerHTML = `
                    <strong><i class="fas fa-search"></i> ПРОВЕРКА...</strong>
                    Запущена AI проверка<br>
                    <small>Результат будет через несколько секунд</small>
                `;
            }
            
        } catch (error) {
            manualResultEl.className = 'check-result danger show';
            manualResultEl.innerHTML = `
                <strong><i class="fas fa-exclamation-circle"></i> ОШИБКА</strong>
                ${error.message}<br>
                <small>Проверьте подключение к API</small>
            `;
        }
    }

    checkCurrentPageBtn.addEventListener('click', async () => {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (tab && tab.url) {
            await manualCheck(tab.url);
        }
    });

    manualCheckBtn.addEventListener('click', () => {
        if (manualCheckSection.style.display === 'none' || manualCheckSection.style.display === '') {
            manualCheckSection.style.display = 'block';
            manualUrlInput.focus();
        } else {
            manualCheckSection.style.display = 'none';
            manualResultEl.classList.remove('show');
        }
    });

    submitCheckBtn.addEventListener('click', () => {
        const url = manualUrlInput.value.trim();
        if (url) {
            manualCheck(url);
        }
    });

    manualUrlInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            const url = manualUrlInput.value.trim();
            if (url) {
                manualCheck(url);
            }
        }
    });

    detailedStatsBtn.addEventListener('click', async () => {
        const response = await new Promise((resolve) => {
            chrome.runtime.sendMessage(
                { type: 'GET_STATS' },
                (response) => {
                    if (chrome.runtime.lastError) {
                        console.error('Ошибка:', chrome.runtime.lastError);
                        resolve(null);
                    } else {
                        resolve(response);
                    }
                }
            );
        });
        
        if (response && response.success) {
            const safePercent = response.total > 0 
                ? Math.round((response.safe / response.total) * 100) 
                : 0;
            const blockedPercent = response.total > 0 
                ? Math.round((response.blocked / response.total) * 100) 
                : 0;
            const unknownPercent = response.total > 0 
                ? Math.round((response.unknown / response.total) * 100) 
                : 0;
            
            alert(`📊 Детальная статистика АнтиФиш:\n\n` +
                  `✅ Безопасные сайты: ${response.safe || 0} (${safePercent}%)\n` +
                  `🚫 Заблокировано: ${response.blocked || 0} (${blockedPercent}%)\n` +
                  `🔍 Не определено: ${response.unknown || 0} (${unknownPercent}%)\n` +
                  `📈 Проверок сегодня: ${response.today || 0}\n` +
                  `📆 Проверок за неделю: ${response.week || 0}\n` +
                  `🔢 Всего проверок: ${response.total || 0}\n\n` +
                  `🛡️ Защита работает эффективно!`);
        } else {
            alert('Не удалось загрузить статистику');
        }
    });

    viewHistoryBtn.addEventListener('click', () => {
        chrome.tabs.create({ 
            url: chrome.runtime.getURL('history.html') || 
                 'chrome://extensions/?id=' + chrome.runtime.id 
        });
    });

    clearCacheBtn.addEventListener('click', async () => {
        if (confirm('Очистить кэш проверок? Это удалит временные данные.')) {
            chrome.runtime.sendMessage({ type: 'CLEAR_CACHE' });
            
            stats.today = 0;
            stats.week = 0;
            stats.total = 0;
            stats.blocked = 0;
            
            todayChecksEl.textContent = '0';
            weekChecksEl.textContent = '0';
            totalChecksEl.textContent = '0';
            blockedCountEl.textContent = '0';
            
            alert('Кэш очищен!');
        }
    });

    init();
});