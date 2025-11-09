FROM python:3.11-slim

WORKDIR /app

# Instalar dependencias del sistema
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copiar archivos de requerimientos
COPY requirements.txt .

# Instalar dependencias de Python
FROM python:3.11-slim

WORKDIR /app

# Instalar dependencias del sistema
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copiar archivos de requerimientos
COPY requirements.txt .

# Instalar dependencias de Python
RUN pip install --no-cache-dir -r requirements.txt

# Copiar estructura del proyecto
COPY backend/ ./backend/
COPY frontend/ ./frontend/
COPY attack/ ./attack/

# Cambiar al directorio backend para ejecución
WORKDIR /app/backend

# Exponer puerto
EXPOSE 5000

# Comando de inicio
CMD ["python", "app.py"]