console.log('Контент-скрипт АнтиФиш загружен');

function getPageContent() {
    try {
        const clone = document.documentElement.cloneNode(true);
        const scripts = clone.querySelectorAll('script, style, noscript, iframe');
        scripts.forEach(el => el.remove());
        
        let text = clone.innerText || clone.textContent || '';
        text = text.replace(/\s+/g, ' ').trim();
        return text.substring(0, 5000);
    } catch (error) {
        console.error('Ошибка получения контента:', error);
        return '';
    }
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    switch(request.type) {
        case 'GET_PAGE_CONTENT':
            const content = getPageContent();
            sendResponse({ content: content });
            break;
            
        case 'GET_CHECK_STATUS':
            sendResponse({ 
                url: window.location.href,
                title: document.title,
                contentLength: getPageContent().length
            });
            break;
    }
    
    return true;
});

document.addEventListener('click', function(event) {
    let target = event.target;
    
    while (target && target.tagName !== 'A') {
        target = target.parentElement;
        if (!target) return;
    }

    const url = target.href;
    if (!url || url.startsWith('#') || url.startsWith('javascript:')) return;

    if (url.startsWith(window.location.origin)) return;

    console.log('Обнаружен клик по ссылке:', url);
    
    chrome.runtime.sendMessage(
        { type: 'CHECK_LINK', url: url },
        (response) => {
            if (response && response.block) {
                console.log('Ссылка опасна, блокируем:', url);
                event.preventDefault();
                event.stopPropagation();
                showWarning(target, url, response.data);
            }
        }
    );
}, true);

function showWarning(element, url, data) {
    const warning = document.createElement('div');
    
    let message = '⚠️ Возможная фишинг-ссылка';
    if (data && data.source) {
        message += ` (обнаружено: ${data.source})`;
    }
    
    warning.innerHTML = `
        <div style="
            position: fixed;
            top: 20px;
            right: 20px;
            background: #ffebee;
            border: 2px solid #f44336;
            padding: 15px;
            border-radius: 8px;
            z-index: 10000;
            max-width: 350px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            font-family: Arial, sans-serif;
        ">
            <strong style="color: #c62828; display: block; margin-bottom: 8px;">
                ${message}
            </strong>
            <div style="display: flex; gap: 10px; margin-top: 10px;">
                <button id="cancel-btn" style="
                    flex: 1;
                    background: #2196f3;
                    color: white;
                    border: none;
                    padding: 8px;
                    border-radius: 4px;
                    cursor: pointer;
                    font-size: 13px;
                ">Отмена</button>
                <button id="proceed-btn" style="
                    flex: 1;
                    background: #f44336;
                    color: white;
                    border: none;
                    padding: 8px;
                    border-radius: 4px;
                    cursor: pointer;
                    font-size: 13px;
                ">Перейти</button>
            </div>
        </div>
    `;

    document.body.appendChild(warning);

    warning.querySelector('#cancel-btn').addEventListener('click', () => {
        document.body.removeChild(warning);
    });

    warning.querySelector('#proceed-btn').addEventListener('click', () => {
        document.body.removeChild(warning);
        window.open(url, '_blank');
    });

    setTimeout(() => {
        if (document.body.contains(warning)) {
            document.body.removeChild(warning);
        }
    }, 15000);
}