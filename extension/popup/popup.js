'use strict';

document.addEventListener('DOMContentLoaded', async () => {

    // ── Элементы ──────────────────────────────────────────────────────────
    const currentUrlEl   = document.getElementById('currentUrl');
    const siteStatusEl   = document.getElementById('siteStatus');
    const currentSiteEl  = document.getElementById('currentSite');
    const siteIconEl     = document.getElementById('siteIcon');

    const todayChecksEl  = document.getElementById('todayChecks');
    const weekChecksEl   = document.getElementById('weekChecks');
    const safeCountEl    = document.getElementById('safeCount');
    const blockedCountEl = document.getElementById('blockedCount');
    const updateTimeEl   = document.getElementById('updateTime');

    const settingsBtn    = document.getElementById('settingsBtn');
    const planChip       = document.getElementById('planChip');
    const checkCurrentBtn = document.getElementById('checkCurrentPage');
    const manualCheckBtn = document.getElementById('manualCheckBtn');
    const manualSection  = document.getElementById('manualSection');
    const manualUrlInput = document.getElementById('manualUrl');
    const submitCheckBtn = document.getElementById('submitCheck');
    const manualResultEl = document.getElementById('manualResult');
    const clearCacheBtn  = document.getElementById('clearCacheBtn');

    // ── Загрузка настроек ─────────────────────────────────────────────────
    let settings = { apiUrl: 'http://localhost:8787', apiKey: '', plan: 'free', darkMode: false, sensitivity: 65 };
    try {
        settings = await new Promise(res =>
            chrome.storage.sync.get({
                apiUrl: 'http://localhost:8787', apiKey: '', plan: 'free',
                darkMode: false, sensitivity: 65,
            }, data => res({ ...settings, ...data }))
        );
    } catch (_) {}

    // Тёмная тема
    if (settings.darkMode) document.body.classList.add('dark');

    // Премиум-чип
    if (settings.plan === 'premium') {
        planChip.style.display = 'inline-block';
        planChip.title = 'Премиум-план активен';
    }

    function getApiBase() {
        return (settings.apiUrl || '').replace(/\/$/, '') + '/api/v1';
    }
    function buildHeaders() {
        const h = { 'Content-Type': 'application/json' };
        if (settings.apiKey) h['X-API-Key'] = settings.apiKey;
        return h;
    }
    function getThreshold() { return (settings.sensitivity || 65) / 100; }

    // ── Статистика ────────────────────────────────────────────────────────
    async function loadStats() {
        try {
            const resp = await sendBg({ type: 'GET_STATS' });
            if (resp?.success) {
                todayChecksEl.textContent  = resp.today   || 0;
                weekChecksEl.textContent   = resp.week    || 0;
                safeCountEl.textContent    = resp.safe    || 0;
                blockedCountEl.textContent = resp.blocked || 0;
            }
        } catch (_) {}
    }

    // ── Информация о текущей вкладке ──────────────────────────────────────
    async function updateCurrentTab() {
        try {
            const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
            if (!tab?.url || tab.url.startsWith('chrome://') || tab.url.startsWith('chrome-extension://')) {
                currentUrlEl.textContent = 'Системная страница';
                setSiteState('unknown', '— Нет данных');
                return;
            }

            const url = new URL(tab.url);
            currentUrlEl.textContent = url.hostname + (url.pathname !== '/' ? url.pathname.substring(0, 30) : '');

            const cached = await sendBg({ type: 'GET_CHECK_STATUS', url: tab.url });
            if (cached?.checked && cached.result) {
                renderSiteResult(cached.result);
            } else {
                setSiteState('checking', 'Проверка…', true);
            }
        } catch (err) {
            currentUrlEl.textContent = 'Ошибка';
            setSiteState('unknown', 'Ошибка загрузки');
        }
    }

    function renderSiteResult(result) {
        if (result.phishing === true) {
            setSiteState('danger', 'Опасный сайт');
        } else if (result.phishing === false) {
            setSiteState('safe', 'Безопасен');
        } else {
            setSiteState('checking', 'Анализируется…', true);
        }
    }

    function setSiteState(state, label, spinning = false) {
        currentSiteEl.className = 'current-site ' + (state === 'checking' ? 'warning' : state);
        siteStatusEl.innerHTML = spinning
            ? `<span class="spin-icon">⟳</span> ${label}`
            : `<span>${_stateIcon(state)}</span> ${label}`;
    }

    function _stateIcon(state) {
        return { safe: '✓', danger: '✕', warning: '!', unknown: '?' }[state] || '';
    }

    // ── Время ─────────────────────────────────────────────────────────────
    function updateTime() {
        updateTimeEl.textContent = new Date().toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' });
    }

    // ── Ручная проверка ────────────────────────────────────────────────────
    async function runManualCheck(url) {
        if (!url) return;
        url = url.trim();
        if (!/^https?:\/\//i.test(url)) url = 'http://' + url;

        manualResultEl.innerHTML = '<span class="spin-icon">⟳</span> Проверяем…';
        manualResultEl.className = 'check-result warning show';

        try {
            // Используем AI-эндпоинт для точной проверки
            const resp = await fetch(`${getApiBase()}/ai`, {
                method:  'POST',
                headers: buildHeaders(),
                body:    JSON.stringify({ link: url, threshold: getThreshold() }),
            });
            if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
            const result = await resp.json();

            sendBg({ type: 'UPDATE_STATS', result });
            await loadStats();

            if (result.phishing === true) {
                const pct = result.chance ? ` (${Math.round(result.chance * 100)}%)` : '';
                manualResultEl.className = 'check-result danger show';
                manualResultEl.innerHTML =
                    `<strong>⚠ ОПАСНО${pct}</strong>Фишинговый сайт обнаружен<br>` +
                    `<small>Источник: ${_sourceLabel(result.source)}</small>`;
            } else if (result.phishing === false) {
                manualResultEl.className = 'check-result safe show';
                manualResultEl.innerHTML =
                    `<strong>✓ БЕЗОПАСНО</strong>Сайт проверен, угроз нет<br>` +
                    `<small>Источник: ${_sourceLabel(result.source)}</small>`;
            } else {
                manualResultEl.className = 'check-result warning show';
                manualResultEl.innerHTML =
                    `<strong>? НЕ ОПРЕДЕЛЕНО</strong>Запущена расширенная проверка<br>` +
                    `<small>Результат будет через несколько секунд</small>`;
            }
        } catch (err) {
            manualResultEl.className = 'check-result danger show';
            manualResultEl.innerHTML =
                `<strong>✕ ОШИБКА</strong>${escHtml(err.message)}<br>` +
                `<small>Проверьте подключение к серверу в настройках</small>`;
        }
    }

    function _sourceLabel(src) {
        return { blacklist: 'чёрный список', whitelist: 'белый список', ai_url: 'AI-анализ URL', ai_content: 'AI-анализ контента' }[src] || src || 'неизвестно';
    }

    function escHtml(s) {
        return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
    }

    // ── Обёртка sendMessage ────────────────────────────────────────────────
    function sendBg(msg) {
        return new Promise(resolve => {
            chrome.runtime.sendMessage(msg, resp => {
                if (chrome.runtime.lastError) resolve(null);
                else resolve(resp);
            });
        });
    }

    // ── Обработчики событий ───────────────────────────────────────────────
    settingsBtn.addEventListener('click', () => chrome.runtime.openOptionsPage());

    checkCurrentBtn.addEventListener('click', async () => {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (tab?.url) runManualCheck(tab.url);
    });

    manualCheckBtn.addEventListener('click', () => {
        manualSection.classList.toggle('open');
        if (manualSection.classList.contains('open')) manualUrlInput.focus();
        else {
            manualResultEl.className = 'check-result';
        }
    });

    submitCheckBtn.addEventListener('click', () => runManualCheck(manualUrlInput.value));

    manualUrlInput.addEventListener('keypress', e => {
        if (e.key === 'Enter') runManualCheck(manualUrlInput.value);
    });

    clearCacheBtn.addEventListener('click', async () => {
        if (!confirm('Очистить кэш проверок?\nЭто удалит временные данные о проверенных сайтах.')) return;
        await sendBg({ type: 'CLEAR_CACHE' });
    });

    // ── Инициализация ─────────────────────────────────────────────────────
    updateTime();
    setInterval(updateTime, 30_000);

    await Promise.all([loadStats(), updateCurrentTab()]);
    setInterval(updateCurrentTab, 6_000);
});
