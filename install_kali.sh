#!/bin/bash

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}Iniciando instalación del Sistema de Auditoría de Seguridad en Kali Linux...${NC}"

# Actualizar sistema
echo -e "${YELLOW}Actualizando sistema...${NC}"
sudo apt update && sudo apt upgrade -y

# Instalar solo las dependencias necesarias
echo -e "${YELLOW}Instalando dependencias del sistema...${NC}"
sudo apt install -y \
    postgresql \
    postgresql-contrib \
    redis-server \
    bloodhound \
    libnfnetlink-dev \
    libldap2-dev \
    libsasl2-dev \
    python3-lsassy \
    faraday \
    mitmproxy \
    certipy-ad \
    patator \
    netexec \
    faraday-cli \
    theharvester \
    sslyze

# Crear directorio del proyecto
echo -e "${YELLOW}Creando estructura de directorios...${NC}"
sudo mkdir -p /opt/pentest/{reports,temp,evidence,loot,wordlists}
sudo chown -R $USER:$USER /opt/pentest

# Instalar dependencias Python
echo -e "${YELLOW}Instalando dependencias Python...${NC}"
# Primero actualizamos pip
python3 -m pip install --upgrade pip --break-system-packages

# Instalamos solo las dependencias que no están en los repositorios de Kali
pip3 install --user --no-cache-dir -r requirements.txt --break-system-packages

# Instalar Node.js y npm si no están instalados
echo -e "${YELLOW}Instalando Node.js y npm...${NC}"
sudo apt install -y nodejs npm

# Instalar n8n
echo -e "${YELLOW}Instalando n8n...${NC}"
sudo npm install n8n -g

# Configurar PostgreSQL
echo -e "${YELLOW}Configurando PostgreSQL...${NC}"
sudo -u postgres psql -c "CREATE USER pentest WITH PASSWORD 'pentest123';"
sudo -u postgres psql -c "CREATE DATABASE pentest_db OWNER pentest;"

# Configurar Redis
echo -e "${YELLOW}Configurando Redis...${NC}"
sudo systemctl enable redis-server
sudo systemctl start redis-server

# Configurar Nginx
echo -e "${YELLOW}Configurando Nginx...${NC}"
sudo tee /etc/nginx/sites-available/pentest << EOF
server {
    listen 80;
    server_name localhost;

    location / {
        proxy_pass http://localhost:5678;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_cache_bypass \$http_upgrade;
    }
}
EOF

sudo ln -s /etc/nginx/sites-available/pentest /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx

# Crear script para iniciar n8n
echo -e "${YELLOW}Creando script de inicio para n8n...${NC}"
sudo tee /usr/local/bin/start-n8n << EOF
#!/bin/bash
export N8N_PORT=5678
export N8N_PROTOCOL=http
export N8N_USER_MANAGEMENT_DISABLED=true
export N8N_BASIC_AUTH_ACTIVE=false
export NODE_ENV=production
n8n start
EOF

sudo chmod +x /usr/local/bin/start-n8n

echo -e "${GREEN}Instalación completada!${NC}"
echo -e "${YELLOW}Para iniciar n8n, ejecuta: start-n8n${NC}"
echo -e "${YELLOW}Accede a la interfaz web en: http://localhost${NC}"
echo -e "${YELLOW}El sistema está listo para usar.${NC}" 