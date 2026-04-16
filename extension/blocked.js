function extractDomain(url) {
    try {
        const urlObj = new URL(url);
        let domain = urlObj.hostname;
        
        if (domain.startsWith('www.')) {
            domain = domain.substring(4);
        }
        
        return domain;
    } catch (e) {
        const match = url.match(/^(?:https?:\/\/)?(?:[^@\n]+@)?(?:www\.)?([^:/\n?]+)/);
        return match ? match[1] : url;
    }
}

async function addToWhitelist(domain) {
    const loadingSpan = document.createElement('span');
    loadingSpan.className = 'loading';
    
    const reportBtn = document.getElementById('reportBtn');
    const originalHtml = reportBtn.innerHTML;
    reportBtn.innerHTML = '';
    reportBtn.appendChild(loadingSpan);
    reportBtn.appendChild(document.createTextNode(' Отправка...'));
    reportBtn.disabled = true;
    
    try {
        const response = await fetch('http://localhost:8787/api/v1/whitelist', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                link: domain
            })
        });
        
        if (response.ok) {
            if (typeof chrome !== 'undefined' && chrome.runtime) {
                const params = new URLSearchParams(window.location.search);
                const blockedUrl = params.get('url') || '';
                
                chrome.runtime.sendMessage({
                    type: 'REMOVE_FROM_CACHE',
                    url: blockedUrl
                }, (response) => {
                    console.log('URL удален из кэша расширения');
                });
            }
            
            reportBtn.innerHTML = '<i class="fas fa-check-circle"></i> Отправлено';
            reportBtn.classList.add('success');
            
            setTimeout(() => {
                alert(`✅ Спасибо! Домен "${domain}" отправлен на проверку.\n\nБлокировка будет перепроверена при следующем заходе на сайт.`);
            }, 100);
            
        } else {
            throw new Error(`HTTP ${response.status}`);
        }
        
    } catch (error) {
        console.error('Ошибка при отправке:', error);
        
        reportBtn.innerHTML = '<i class="fas fa-exclamation-circle"></i> Ошибка отправки';
        reportBtn.classList.add('error');
        
        setTimeout(() => {
            reportBtn.innerHTML = originalHtml;
            reportBtn.disabled = false;
            reportBtn.classList.remove('error');
        }, 3000);
        
        alert('❌ Ошибка при отправке отчета. Пожалуйста, попробуйте позже.');
    }
}

function updatePageData(blockedUrl, source, risk) {
    document.getElementById('blockedUrl').textContent = blockedUrl || 'Неизвестный URL';
    document.getElementById('blockSource').textContent = source || 'unknown';
    document.getElementById('riskLevel').textContent = (risk || 'Высокий') + ' риск';
    
    const now = new Date();
    document.getElementById('blockTime').textContent = 
        now.toLocaleString('ru-RU', {
            year: 'numeric',
            month: 'long',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        });
    
    document.getElementById('timestamp').textContent = 
        'ID события: ' + Date.now();
}

function setupGoBackButton() {
    document.getElementById('goBackBtn').addEventListener('click', () => {
        if (typeof chrome !== 'undefined' && chrome.tabs) {
            if (window.history.length > 1) {
                window.history.back();
            } else {
                chrome.tabs.create({ url: 'chrome://newtab' }, () => {
                    setTimeout(() => {
                        chrome.tabs.getCurrent((tab) => {
                            if (tab && tab.id) {
                                chrome.tabs.remove(tab.id);
                            } else {
                                window.close();
                            }
                        });
                    }, 100);
                });
            }
        } else {
            if (window.history.length > 1) {
                window.history.back();
            } else {
                window.close();
            }
        }
    });
}

function setupReportButton() {
    document.getElementById('reportBtn').addEventListener('click', () => {
        const params = new URLSearchParams(window.location.search);
        const blockedUrl = params.get('url') || '';
        
        if (!blockedUrl) {
            alert('❌ Не удалось определить URL сайта');
            return;
        }
        
        const domain = extractDomain(blockedUrl);
        
        if (confirm(
            '⚠️ ВНИМАНИЕ!\n\n' +
            'Вы уверены, что хотите сообщить об ошибке?\n\n' +
            `Домен: ${domain}\n` +
            `URL: ${blockedUrl}\n\n` +
            'Это действие:\n' +
            '• Отправит домен на проверку администратору\n' +
            '• Удалит текущую блокировку из кэша\n' +
            '• Если сайт безопасен, он будет добавлен в белый список\n' +
            '• Блокировка будет перепроверена при следующем заходе\n\n' +
            'Продолжить?'
        )) {
            addToWhitelist(domain);
        }
    });
}

function setupProceedButton() {
    document.getElementById('proceedBtn').addEventListener('click', () => {
        const params = new URLSearchParams(window.location.search);
        const blockedUrl = params.get('url') || '';
        
        if (!blockedUrl) {
            alert('❌ Не удалось определить URL сайта');
            return;
        }
        
        if (confirm(
            '⚠️ ВНИМАНИЕ!\n\n' +
            'Вы собираетесь перейти на сайт, который был заблокирован ' +
            'системой безопасности.\n\n' +
            'Этот сайт может:\n' +
            '• Украсть ваши пароли\n' +
            '• Получить доступ к банковским данным\n' +
            '• Установить вредоносное ПО\n' +
            '• Заразить устройство вирусами\n\n' +
            '🔒 Рекомендации:\n' +
            '• Используйте виртуальную клавиатуру\n' +
            '• Не вводите пароли и платежные данные\n' +
            '• Проверьте адресную строку\n' +
            '• Используйте двухфакторную аутентификацию\n\n' +
            'Переход выполняется на ваш страх и риск!\n' +
            'Вы уверены, что хотите продолжить?'
        )) {
            if (typeof chrome !== 'undefined' && chrome.runtime) {
                chrome.runtime.sendMessage({
                    type: 'ADD_MANUAL_BYPASS',
                    url: blockedUrl
                }, (response) => {
                    console.log('Ручной bypass установлен');
                });
            }
            
            if (typeof chrome !== 'undefined' && chrome.tabs) {
                chrome.tabs.create({ 
                    url: blockedUrl, 
                    active: true 
                }, (newTab) => {
                    setTimeout(() => {
                        chrome.tabs.getCurrent((currentTab) => {
                            if (currentTab && currentTab.id) {
                                chrome.tabs.remove(currentTab.id);
                            } else {
                                window.close();
                            }
                        });
                    }, 1000);
                });
            } else {
                window.location.href = blockedUrl;
            }
        }
    });
}

document.addEventListener('DOMContentLoaded', () => {
    const params = new URLSearchParams(window.location.search);
    const blockedUrl = params.get('url') || '';
    const source = params.get('source') || 'unknown';
    const risk = params.get('risk') || 'Высокий';
    
    updatePageData(blockedUrl, source, risk);
    
    setupGoBackButton();
    setupReportButton();
    setupProceedButton();
    
    document.addEventListener('keydown', (e) => {
        switch(e.key) {
            case 'Escape':
                document.getElementById('goBackBtn').click();
                break;
            case 'r':
            case 'R':
                if (e.ctrlKey) {
                    document.getElementById('reportBtn').click();
                }
                break;
            case 'Enter':
                if (e.altKey) {
                    document.getElementById('proceedBtn').click();
                }
                break;
        }
    });
});