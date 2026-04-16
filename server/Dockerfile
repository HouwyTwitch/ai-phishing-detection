FROM python:3.11-slim

# Метаданные
LABEL maintainer="Назаров А.А. <antiphish@example.ru>" \
      version="1.1.0" \
      description="АнтиФиш — API-сервер обнаружения фишинга"

# Системные зависимости
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libssl-dev \
        libffi-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Сначала устанавливаем зависимости (кэшируемый слой)
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Копируем исходный код
COPY . .

# Создаём директории для логов и ассетов
RUN mkdir -p logs assets

# Создаём непривилегированного пользователя
RUN useradd -m -u 1001 antiphish && chown -R antiphish:antiphish /app
USER antiphish

# Порт
EXPOSE 8787

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8787/health')" \
    || exit 1

# Запуск
CMD ["python", "app.py"]
