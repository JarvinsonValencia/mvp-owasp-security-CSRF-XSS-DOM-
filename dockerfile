FROM python:3.11-slim

# Directorio base
WORKDIR /app

# Instalar dependencias del sistema
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copiar requirements primero (mejor cache)
COPY requirements.txt .

# Instalar dependencias de Python
RUN pip install --no-cache-dir -r requirements.txt

# Copiar proyecto completo
COPY backend/ ./backend/
COPY frontend/ ./frontend/
COPY attack/ ./attack/

# Posicionar backend como directorio de ejecución
WORKDIR /app/backend

# Exponer puerto
EXPOSE 5000

# Ejecutar la app
CMD ["python", "app.py"]
