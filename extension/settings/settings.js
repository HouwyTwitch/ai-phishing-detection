'use strict';

// ── Дефолтные настройки ────────────────────────────────────────────────────
const DEFAULTS = {
    apiUrl:           'http://localhost:8787',
    apiKey:           '',
    sensitivity:      65,
    checkMode:        'auto',
    notifEnabled:     true,
    linkWarning:      true,
    darkMode:         false,
    plan:             'free',
    licenseKey:       '',
};

let _original = {};  // для обнаружения изменений

// ── Утилиты ────────────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);

function setDot(id, state) {  // state: 'green' | 'yellow' | 'red' | ''
    const dot = $(id);
    if (!dot) return;
    dot.className = 'status-dot' + (state ? ' ' + state : '');
}

function setSaveHint(msg, type = '') {
    const el = $('saveHint');
    el.textContent = msg;
    el.className = 'save-hint' + (type ? ' ' + type : '');
}

// ── Применение тёмной темы ─────────────────────────────────────────────────
function applyDarkMode(enabled) {
    document.body.classList.toggle('dark', enabled);
}

// ── Отображение плана ──────────────────────────────────────────────────────
function renderPlan(plan) {
    const badge = $('planBadge');
    if (plan === 'premium') {
        badge.textContent = '⭐ Премиум';
        badge.classList.add('premium');
        $('premiumBox').classList.add('active');
        $('premiumBox').innerHTML = `
            <div class="premium-icon">✅</div>
            <div class="premium-text">
                <strong>Премиум активен</strong>
                <p>Анализ контента страниц, расширенная защита и приоритетные обновления включены.</p>
            </div>`;
    } else {
        badge.textContent = 'Бесплатный';
        badge.classList.remove('premium');
    }
}

// ── Загрузка настроек из chrome.storage ───────────────────────────────────
async function loadSettings() {
    return new Promise(resolve => {
        chrome.storage.sync.get(DEFAULTS, data => {
            if (chrome.runtime.lastError) {
                console.error('Ошибка чтения настроек:', chrome.runtime.lastError);
                resolve({ ...DEFAULTS });
            } else {
                resolve({ ...DEFAULTS, ...data });
            }
        });
    });
}

// ── Применение настроек к форме ────────────────────────────────────────────
function applyToForm(s) {
    $('apiUrl').value        = s.apiUrl;
    $('apiKey').value        = s.apiKey;
    $('sensitivity').value   = s.sensitivity;
    $('sensitivityVal').textContent = s.sensitivity + '%';
    $('notifEnabled').checked  = s.notifEnabled;
    $('linkWarning').checked   = s.linkWarning;
    $('darkMode').checked      = s.darkMode;
    $('licenseKey').value      = s.licenseKey;

    document.querySelectorAll('input[name="checkMode"]').forEach(r => {
        r.checked = r.value === s.checkMode;
    });

    applyDarkMode(s.darkMode);
    renderPlan(s.plan);
}

// ── Сбор данных формы ──────────────────────────────────────────────────────
function collectForm() {
    const checkModeEl = document.querySelector('input[name="checkMode"]:checked');
    return {
        apiUrl:       ($('apiUrl').value || '').trim().replace(/\/$/, ''),
        apiKey:       ($('apiKey').value || '').trim(),
        sensitivity:  parseInt($('sensitivity').value, 10),
        checkMode:    checkModeEl ? checkModeEl.value : 'auto',
        notifEnabled: $('notifEnabled').checked,
        linkWarning:  $('linkWarning').checked,
        darkMode:     $('darkMode').checked,
        // plan и licenseKey обрабатываются отдельно
    };
}

// ── Проверка подключения ───────────────────────────────────────────────────
async function testConnection(url, apiKey) {
    try {
        const headers = { 'Content-Type': 'application/json' };
        if (apiKey) headers['X-API-Key'] = apiKey;

        const res = await fetch(`${url}/health`, { method: 'GET', headers, signal: AbortSignal.timeout(5000) });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        return await res.json();
    } catch (err) {
        throw new Error(err.message || 'Недоступен');
    }
}

async function runConnectionTest() {
    const url    = ($('apiUrl').value || '').trim().replace(/\/$/, '');
    const apiKey = ($('apiKey').value || '').trim();

    setDot('connDot', 'yellow');
    $('connStatus').textContent = 'Проверка…';
    setDot('modelDot', '');
    $('modelStatus').textContent = '—';
    setDot('blDot', '');
    $('blStatus').textContent = '—';

    try {
        const data = await testConnection(url, apiKey);
        setDot('connDot', 'green');
        $('connStatus').textContent = `v${data.version || '?'} • OK`;

        setDot('modelDot', data.model_loaded ? 'green' : 'red');
        $('modelStatus').textContent = data.model_loaded ? 'Загружена' : 'Не загружена';

        setDot('blDot', 'green');
        $('blStatus').textContent = `${(data.blacklist_size || 0).toLocaleString('ru')} доменов`;
    } catch (err) {
        setDot('connDot', 'red');
        $('connStatus').textContent = err.message;
    }
}

// ── Активация лицензии ─────────────────────────────────────────────────────
async function activateLicense(key) {
    const status = $('licenseStatus');
    // Формат ключа: APF-XXXX-XXXX-XXXX (4 hex-символа в каждой группе)
    const valid = /^APF-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}$/i.test(key.trim());
    if (!valid) {
        status.textContent = '✗ Неверный формат ключа (ожидается APF-XXXX-XXXX-XXXX)';
        status.className = 'license-status err';
        return false;
    }

    const url = ($('apiUrl').value || '').trim().replace(/\/$/, '');
    const apiKey = ($('apiKey').value || '').trim();
    status.textContent = 'Проверка на сервере…';
    status.className = 'license-status';

    try {
        const headers = { 'Content-Type': 'application/json' };
        if (apiKey) headers['X-API-Key'] = apiKey;
        const res = await fetch(`${url}/api/v1/license/verify`, {
            method: 'POST',
            headers,
            body: JSON.stringify({ key: key.trim() }),
            signal: AbortSignal.timeout(8000),
        });
        const data = await res.json();
        if (!res.ok || !data.valid) {
            status.textContent = '✗ Лицензия недействительна или истёк срок действия';
            status.className = 'license-status err';
            return false;
        }
        const plan = data.plan || 'premium';
        const expires = data.expires ? ` (до ${data.expires})` : ' (бессрочная)';
        status.textContent = `✓ Лицензия активирована · ${plan}${expires}`;
        status.className = 'license-status ok';
        return true;
    } catch (err) {
        status.textContent = '✗ Не удалось проверить лицензию на сервере';
        status.className = 'license-status err';
        return false;
    }
}

// ── Статистика ─────────────────────────────────────────────────────────────
async function loadStats() {
    return new Promise(resolve => {
        chrome.runtime.sendMessage({ type: 'GET_STATS' }, resp => {
            if (chrome.runtime.lastError || !resp) resolve(null);
            else resolve(resp);
        });
    });
}

async function refreshStats() {
    const s = await loadStats();
    if (s) {
        $('smTotal').textContent   = (s.total   || 0).toLocaleString('ru');
        $('smBlocked').textContent = (s.blocked || 0).toLocaleString('ru');
        $('smSafe').textContent    = (s.safe    || 0).toLocaleString('ru');
    }
}

// ── Сохранение ────────────────────────────────────────────────────────────
async function saveSettings() {
    const btn = $('saveBtn');
    btn.disabled = true;
    setSaveHint('Сохранение…');

    try {
        const current = await loadSettings();
        const form = collectForm();
        const merged = { ...current, ...form };

        // Обработка лицензионного ключа
        const newKey = ($('licenseKey').value || '').trim();
        if (newKey && newKey !== current.licenseKey) {
            const ok = await activateLicense(newKey);
            if (ok) {
                merged.licenseKey = newKey;
                merged.plan = 'premium';
            }
        } else if (!newKey) {
            merged.licenseKey = '';
            merged.plan = 'free';
        } else {
            merged.licenseKey = current.licenseKey;
            merged.plan = current.plan;
        }

        await new Promise((res, rej) => {
            chrome.storage.sync.set(merged, () => {
                if (chrome.runtime.lastError) rej(chrome.runtime.lastError);
                else res();
            });
        });

        _original = { ...merged };
        applyDarkMode(merged.darkMode);
        renderPlan(merged.plan);
        setSaveHint('✓ Настройки сохранены', 'ok');
        setTimeout(() => setSaveHint(''), 3000);
    } catch (err) {
        console.error('Ошибка сохранения:', err);
        setSaveHint('✗ Ошибка сохранения', 'err');
    } finally {
        btn.disabled = false;
    }
}

// ── Инициализация ──────────────────────────────────────────────────────────
async function init() {
    const settings = await loadSettings();
    _original = { ...settings };
    applyToForm(settings);
    await refreshStats();
    runConnectionTest();  // не ждём

    // ── Слайдер чувствительности ──
    $('sensitivity').addEventListener('input', () => {
        $('sensitivityVal').textContent = $('sensitivity').value + '%';
    });

    // ── Тёмная тема (live preview) ──
    $('darkMode').addEventListener('change', () => {
        applyDarkMode($('darkMode').checked);
    });

    // ── Показать/скрыть API-ключ ──
    $('toggleKey').addEventListener('click', () => {
        const input = $('apiKey');
        input.type = input.type === 'password' ? 'text' : 'password';
    });

    // ── Тест подключения ──
    $('testConn').addEventListener('click', runConnectionTest);

    // ── Активация лицензии ──
    $('activateBtn').addEventListener('click', async () => {
        const key = ($('licenseKey').value || '').trim();
        if (key) await activateLicense(key);
    });

    // ── Сброс статистики ──
    $('resetStatsBtn').addEventListener('click', async () => {
        if (!confirm('Сбросить всю статистику проверок? Это действие необратимо.')) return;
        await new Promise(res => chrome.runtime.sendMessage({ type: 'RESET_STATS' }, res));
        await refreshStats();
    });

    // ── Сохранение ──
    $('saveBtn').addEventListener('click', saveSettings);

    // ── Отмена ──
    $('cancelBtn').addEventListener('click', () => {
        applyToForm(_original);
        applyDarkMode(_original.darkMode);
        setSaveHint('');
    });

    // ── Keyboard shortcut ──
    document.addEventListener('keydown', e => {
        if ((e.ctrlKey || e.metaKey) && e.key === 's') {
            e.preventDefault();
            saveSettings();
        }
    });
}

document.addEventListener('DOMContentLoaded', init);
