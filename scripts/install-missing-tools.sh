#!/bin/bash

# ============================================================================
# 🔧 INSTALADOR DE HERRAMIENTAS FALTANTES PARA PENTESTING
# ============================================================================
# Instala herramientas que faltan y son requeridas por los scripts
# ============================================================================

echo "🔧 INSTALANDO HERRAMIENTAS FALTANTES"
echo "===================================="

# Función para verificar si una herramienta existe
check_tool() {
    local tool=$1
    local description=$2
    
    if command -v "$tool" >/dev/null 2>&1; then
        echo "✅ $tool - $description (ya instalado)"
        return 0
    else
        echo "❌ $tool - $description (NO ENCONTRADO)"
        return 1
    fi
}

# Función para instalar herramientas
install_tool() {
    local tool=$1
    local package=$2
    local description=$3
    
    echo "📥 Instalando $tool ($description)..."
    
    if sudo apt update >/dev/null 2>&1 && sudo apt install -y "$package" >/dev/null 2>&1; then
        echo "   ✅ $tool instalado correctamente"
        return 0
    else
        echo "   ❌ Error instalando $tool"
        return 1
    fi
}

# Lista de herramientas críticas
echo "🔍 Verificando herramientas necesarias..."
echo "-----------------------------------------"

missing_tools=()

# Verificar herramientas principales
tools=(
    "ssh-audit:ssh-audit:Auditoría de configuración SSH"
    "gobuster:gobuster:Descubrimiento de directorios y DNS"
    "nikto:nikto:Escáner de vulnerabilidades web"
    "nc:netcat-traditional:Cliente/servidor TCP/UDP"
    "hydra:hydra:Herramienta de fuerza bruta"
    "enum4linux:enum4linux:Enumeración SMB/NetBIOS"
    "sslscan:sslscan:Escáner de SSL/TLS"
    "wpscan:wpscan:Escáner de WordPress"
    "sqlmap:sqlmap:Herramienta de inyección SQL"
    "dirb:dirb:Buscador de directorios web"
    "nmap:nmap:Escáner de puertos y red"
    "masscan:masscan:Escáner de puertos masivo"
    "searchsploit:exploitdb:Buscador de exploits"
)

for tool_info in "${tools[@]}"; do
    IFS=':' read -r tool package description <<< "$tool_info"
    if ! check_tool "$tool" "$description"; then
        missing_tools+=("$tool:$package:$description")
    fi
done

# Instalar herramientas faltantes
if [ ${#missing_tools[@]} -eq 0 ]; then
    echo ""
    echo "🎉 ¡Todas las herramientas están instaladas!"
else
    echo ""
    echo "📦 Instalando ${#missing_tools[@]} herramientas faltantes..."
    echo "=================================================="
    
    # Actualizar repositorios
    echo "🔄 Actualizando repositorios..."
    sudo apt update >/dev/null 2>&1
    
    for tool_info in "${missing_tools[@]}"; do
        IFS=':' read -r tool package description <<< "$tool_info"
        install_tool "$tool" "$package" "$description"
    done
fi

# Verificación final
echo ""
echo "🔍 VERIFICACIÓN FINAL"
echo "===================="

all_ok=true
for tool_info in "${tools[@]}"; do
    IFS=':' read -r tool package description <<< "$tool_info"
    if ! check_tool "$tool" "$description"; then
        all_ok=false
    fi
done

# Verificar herramientas específicas para nuestros scripts
echo ""
echo "🎯 Verificando herramientas específicas del proyecto..."
echo "-----------------------------------------------------"

# Verificar nuclei
if [ -f "/usr/bin/nuclei" ]; then
    echo "✅ nuclei - Escáner de vulnerabilidades (ya configurado)"
else
    echo "❌ nuclei - NO encontrado en /usr/bin/nuclei"
    all_ok=false
fi

# Verificar autobloody
if [ -f "/home/kali/.local/bin/autobloody" ]; then
    echo "✅ autobloody - Herramienta AD (ya configurado)"
else
    echo "❌ autobloody - NO encontrado en /home/kali/.local/bin/autobloody"
    all_ok=false
fi

# Verificar ExploitDB
if [ -d "/usr/share/exploitdb" ]; then
    echo "✅ exploitdb - Base de datos de exploits (ya configurado)"
else
    echo "❌ exploitdb - NO encontrado en /usr/share/exploitdb"
    all_ok=false
fi

# Instalar herramientas adicionales específicas
echo ""
echo "🔧 Instalando herramientas adicionales..."
echo "----------------------------------------"

# Instalar ssh-audit desde pip si no está disponible en apt
if ! command -v ssh-audit >/dev/null 2>&1; then
    echo "📥 Instalando ssh-audit desde pip..."
    if pip3 install ssh-audit >/dev/null 2>&1; then
        echo "   ✅ ssh-audit instalado correctamente"
    else
        echo "   ⚠️  Error instalando ssh-audit desde pip"
    fi
fi

# Verificar netcat alternativo
if ! command -v nc >/dev/null 2>&1; then
    echo "📥 Instalando netcat-openbsd como alternativa..."
    sudo apt install -y netcat-openbsd >/dev/null 2>&1
fi

# Resultado final
echo ""
echo "📊 RESUMEN FINAL"
echo "================"

if $all_ok; then
    echo "✅ ¡Todas las herramientas están correctamente instaladas!"
    echo "🚀 Los scripts de explotación deberían funcionar sin problemas"
    
    # Crear script de verificación rápida
    cat > "/home/kali/kali-security-tools/scripts/verify-tools.sh" << 'EOF'
#!/bin/bash
echo "🔍 Verificación rápida de herramientas:"
tools=("nmap" "gobuster" "nikto" "hydra" "nuclei" "ssh-audit" "enum4linux" "sqlmap" "searchsploit")
for tool in "${tools[@]}"; do
    if command -v "$tool" >/dev/null 2>&1; then
        echo "✅ $tool"
    else
        echo "❌ $tool"
    fi
done
EOF
    chmod +x "/home/kali/kali-security-tools/scripts/verify-tools.sh"
    echo "📝 Script de verificación creado: scripts/verify-tools.sh"
    
else
    echo "⚠️  Algunas herramientas aún faltan"
    echo "💡 Puede que necesites instalarlas manualmente"
fi

echo ""
echo "✅ Instalación de herramientas completada" 