import requests
import time
import statistics
import random

API_BASE = "http://localhost:8787/api/v1"

# Тестовые URL для проверки
TEST_URLS = [
    "https://example.com",
    "https://www.google.com", 
    "https://github.com",
    "https://stackoverflow.com",
    "https://yandex.ru"
]

# Тестовый контент для анализа (имитация содержимого страницы)
TEST_CONTENTS = [
    "Добро пожаловать на наш официальный сайт. Введите ваши учетные данные для входа в систему.",
    "Ваш аккаунт был заблокирован. Пожалуйста, подтвердите вашу личность, введя пароль и номер кредитной карты.",
    "Поздравляем! Вы выиграли приз. Для получения награды необходимо указать ваши личные данные.",
    "Техническое обслуживание системы. Требуется обновить информацию о вашей учетной записи.",
    "Безопасное соединение установлено. Этот сайт использует шифрование для защиты ваших данных."
]

def generate_test_content():
    """Генерация тестового контента для анализа"""
    sentences = [
        "Для продолжения работы необходимо авторизоваться в системе.",
        "Введите логин и пароль от вашей учетной записи.",
        "Система обнаружения мошенничества активирована.",
        "Проверка безопасности требует дополнительной информации.",
        "Ваша сессия истекла, пожалуйста, войдите снова.",
        "Подтвердите вашу личность с помощью одноразового кода.",
        "Обновление данных требуется для соблюдения политики безопасности.",
        "Финансовая транзакция ожидает подтверждения.",
        "Служба поддержки рекомендует изменить пароль.",
        "Новое устройство пытается получить доступ к аккаунту."
    ]
    return " ".join(random.sample(sentences, random.randint(3, 7)))

def test_endpoint_fast():
    """Тестирование эндпоинта /fast"""
    times = []
    successful_requests = 0
    
    for url in TEST_URLS:
        for _ in range(20):  # 5 URL * 20 = 100 запросов
            try:
                start = time.perf_counter()
                response = requests.post(
                    f"{API_BASE}/fast",
                    json={"link": url},
                    timeout=3
                )
                response.raise_for_status()
                end = time.perf_counter()
                
                times.append((end - start) * 1000)  # в мс
                successful_requests += 1
                
                # Небольшая пауза между запросами
                time.sleep(0.01)
                
            except requests.exceptions.RequestException as e:
                print(f"Ошибка при запросе к /fast ({url}): {e}")
                continue
    
    if times:
        avg = statistics.mean(times)
        stdev = statistics.stdev(times) if len(times) > 1 else 0
        print(f"/fast: {avg:.1f} ± {stdev:.1f} мс (успешных: {successful_requests}/{len(TEST_URLS)*20})")
    return times

def test_endpoint_ai():
    """Тестирование эндпоинта /ai"""
    times = []
    successful_requests = 0
    
    for url in TEST_URLS:
        for _ in range(20):
            try:
                start = time.perf_counter()
                response = requests.post(
                    f"{API_BASE}/ai",
                    json={"link": url},
                    timeout=5
                )
                response.raise_for_status()
                end = time.perf_counter()
                
                times.append((end - start) * 1000)
                successful_requests += 1
                
                # Пауза для предотвращения перегрузки сервера
                time.sleep(0.05)
                
            except requests.exceptions.RequestException as e:
                print(f"Ошибка при запросе к /ai ({url}): {e}")
                continue
    
    if times:
        avg = statistics.mean(times)
        stdev = statistics.stdev(times) if len(times) > 1 else 0
        print(f"/ai: {avg:.1f} ± {stdev:.1f} мс (успешных: {successful_requests}/{len(TEST_URLS)*20})")
    return times

def test_endpoint_ai_content():
    """Тестирование эндпоинта /ai-content"""
    times = []
    successful_requests = 0
    
    for i, url in enumerate(TEST_URLS):
        for _ in range(20):
            try:
                # Генерация тестового контента
                content = generate_test_content()
                
                start = time.perf_counter()
                response = requests.post(
                    f"{API_BASE}/ai-content",
                    json={
                        "link": url,
                        "content": content
                    },
                    timeout=10  # Увеличенный таймаут для анализа контента
                )
                response.raise_for_status()
                end = time.perf_counter()
                
                times.append((end - start) * 1000)
                successful_requests += 1
                
                # Более длинная пауза для ресурсоемкого анализа
                time.sleep(0.1)
                
            except requests.exceptions.RequestException as e:
                print(f"Ошибка при запросе к /ai-content ({url}): {e}")
                continue
    
    if times:
        avg = statistics.mean(times)
        stdev = statistics.stdev(times) if len(times) > 1 else 0
        print(f"/ai-content: {avg:.1f} ± {stdev:.1f} мс (успешных: {successful_requests}/{len(TEST_URLS)*20})")
    return times

def run_performance_test():
    """Запуск полного теста производительности"""
    print("=" * 60)
    print("Запуск теста производительности API 'АнтиФиш'")
    print("=" * 60)
    
    print("\n1. Тестирование эндпоинта /fast...")
    fast_times = test_endpoint_fast()
    
    print("\n2. Тестирование эндпоинта /ai...")
    ai_times = test_endpoint_ai()
    
    print("\n3. Тестирование эндпоинта /ai-content...")
    ai_content_times = test_endpoint_ai_content()
    
    # Сводная статистика
    print("\n" + "=" * 60)
    print("СВОДНАЯ СТАТИСТИКА ПРОИЗВОДИТЕЛЬНОСТИ")
    print("=" * 60)
    
    if fast_times:
        print(f"• /fast:    {statistics.mean(fast_times):.1f} ± {statistics.stdev(fast_times):.1f} мс")
    if ai_times:
        print(f"• /ai:      {statistics.mean(ai_times):.1f} ± {statistics.stdev(ai_times):.1f} мс")
    if ai_content_times:
        print(f"• /ai-content: {statistics.mean(ai_content_times):.1f} ± {statistics.stdev(ai_content_times):.1f} мс")
    
    # Расчет относительной производительности
    if fast_times and ai_times:
        speedup_fast_to_ai = statistics.mean(ai_times) / statistics.mean(fast_times)
        print(f"\nОтносительная производительность:")
        print(f"• /fast быстрее /ai в {speedup_fast_to_ai:.1f} раз")
    
    if ai_times and ai_content_times:
        speedup_ai_to_content = statistics.mean(ai_content_times) / statistics.mean(ai_times)
        print(f"• /ai быстрее /ai-content в {speedup_ai_to_content:.1f} раз")
    
    return fast_times, ai_times, ai_content_times

def generate_performance_chart(fast_times, ai_times, ai_content_times):
    """Генерация графика производительности (опционально)"""
    try:
        import matplotlib.pyplot as plt
        import numpy as np
        
        # Подготовка данных для графика
        endpoints = ['/fast', '/ai', '/ai-content']
        means = [
            statistics.mean(fast_times) if fast_times else 0,
            statistics.mean(ai_times) if ai_times else 0,
            statistics.mean(ai_content_times) if ai_content_times else 0
        ]
        std_devs = [
            statistics.stdev(fast_times) if len(fast_times) > 1 else 0,
            statistics.stdev(ai_times) if len(ai_times) > 1 else 0,
            statistics.stdev(ai_content_times) if len(ai_content_times) > 1 else 0
        ]
        
        # Создание графика
        fig, ax = plt.subplots(figsize=(10, 6))
        
        x_pos = np.arange(len(endpoints))
        bars = ax.bar(x_pos, means, yerr=std_devs, 
                     align='center', alpha=0.7, ecolor='black', 
                     capsize=10, color=['#4CAF50', '#2196F3', '#FF9800'])
        
        # Настройка графика
        ax.set_ylabel('Время отклика (мс)', fontsize=12)
        ax.set_xlabel('Эндпоинт API', fontsize=12)
        ax.set_title('Производительность эндпоинтов системы "АнтиФиш"', fontsize=14, fontweight='bold')
        ax.set_xticks(x_pos)
        ax.set_xticklabels(endpoints)
        ax.grid(True, axis='y', alpha=0.3)
        
        # Добавление значений на столбцы
        for i, (bar, mean_val) in enumerate(zip(bars, means)):
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height + std_devs[i] + 5,
                   f'{mean_val:.1f} мс', ha='center', va='bottom', fontweight='bold')
        
        plt.tight_layout()
        
        # Сохранение графика
        plt.savefig('api_performance_chart.png', dpi=300, bbox_inches='tight')
        print("\n✓ График производительности сохранен как 'api_performance_chart.png'")
        plt.show()
        
    except ImportError:
        print("\nℹ️ Для построения графика установите matplotlib: pip install matplotlib")
    except Exception as e:
        print(f"\n✗ Ошибка при построении графика: {e}")

if __name__ == "__main__":
    print("Тест производительности API системы 'АнтиФиш'")
    print("Предварительные условия:")
    print("1. Сервер Flask должен быть запущен на http://localhost:8787")
    print("2. Установите необходимые библиотеки: pip install requests matplotlib")
    print("3. Убедитесь, что тестовые URL доступны для проверки")
    print("-" * 60)
    
    input("Нажмите Enter для начала тестирования...")
    
    results = run_performance_test()
    
    # Опциональное построение графика
    if all(results):
        generate_chart = input("\nПостроить график производительности? (y/n): ")
        if generate_chart.lower() == 'y':
            generate_performance_chart(*results)