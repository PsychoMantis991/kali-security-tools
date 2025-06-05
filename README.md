# Kali Security Tools

Herramienta de automatización para auditorías de seguridad que integra diversas herramientas de pentesting en un flujo de trabajo automatizado.

## Estructura del Proyecto

```
kali-security-tools/
├── config/                 # Archivos de configuración
│   ├── port-discovery-config.json
│   ├── service-mapping.json
│   └── service-enum-config.json
├── scripts/               # Scripts de automatización
│   ├── port-discovery.py
│   ├── process-nmap-output.py
│   ├── service-enum.py
│   └── generate_report.py
├── workflows/            # Flujos de trabajo n8n
│   ├── 01-recon-enumeration-new.json
│   └── port-discovery-workflow.json
├── database/            # Base de datos para almacenar resultados
├── results/            # Resultados de los escaneos
├── reports/           # Informes generados
├── temp/             # Archivos temporales
├── tools/           # Herramientas adicionales
├── wordlists/      # Listas de palabras para fuerza bruta
└── install_kali.sh # Script de instalación
```

## Requisitos Previos

- Sistema operativo basado en Debian (preferiblemente Kali Linux)
- Python 3.8 o superior
- Docker y Docker Compose
- n8n para la automatización de flujos de trabajo

## Instalación

1. Clonar el repositorio:
```bash
git clone https://github.com/tu-usuario/kali-security-tools.git
cd kali-security-tools
```

2. Ejecutar el script de instalación:
```bash
chmod +x install_kali.sh
./install_kali.sh
```

El script `install_kali.sh` realiza las siguientes tareas:

- Instala dependencias del sistema:
  - Python y pip
  - Herramientas de desarrollo
  - Bibliotecas necesarias

- Instala herramientas de pentesting:
  - Nmap
  - Masscan
  - Nuclei
  - Gobuster
  - SQLMap
  - Evil-WinRM
  - CrackMapExec
  - Y otras herramientas esenciales

- Configura el entorno:
  - Crea directorios necesarios
  - Configura variables de entorno
  - Instala dependencias de Python
  - Configura n8n

- Verifica la instalación:
  - Comprueba que todas las herramientas están disponibles
  - Verifica la configuración
  - Realiza pruebas básicas

## Configuración

### 1. Configuración de Port Discovery

El archivo `config/port-discovery-config.json` contiene la configuración para el descubrimiento de puertos:

```json
{
    "scan_ports": "1-65535",
    "scan_type": "syn",
    "timing": 2,
    "evasion_techniques": [
        "ttl_manipulation",
        "timing",
        "fragmentation"
    ],
    "default_ports": {
        "low": "-F",
        "medium": "-p-",
        "high": "-p-"
    }
}
```

### 2. Configuración de Servicios

El archivo `config/service-mapping.json` contiene el mapeo de servicios para corregir identificaciones incorrectas:

```json
{
    "service_corrections": {
        "winrm": {
            "correct_service": "winrm",
            "correct_port": 5985,
            "os_requirements": ["Windows"],
            "exploitation_tool": "evil-winrm"
        }
    }
}
```

## Configuración de Workflows en n8n

### Estructura de Workflows

El proyecto incluye tres workflows principales que funcionan de manera integrada:

1. **01-initial-recon.json**: Reconocimiento inicial
   - Descubrimiento de puertos
   - Detección de servicios básicos
   - Identificación del sistema operativo
   - **Activación**: Webhook independiente para escaneos rápidos
   - **Uso**: Ideal para reconocimiento inicial o monitoreo de red

2. **02-service-enumeration.json**: Enumeración detallada de servicios
   - Análisis profundo de servicios detectados
   - Corrección de identificaciones de servicios
   - Mapeo de servicios según el sistema operativo
   - **Activación**: Llamado internamente por el workflow de auditoría completa
   - **Uso**: No se activa directamente, es parte del proceso de auditoría

3. **03-full-audit.json**: Auditoría completa
   - Combinación de los workflows anteriores
   - Incluye fase de explotación
   - Generación de informes
   - Recomendaciones de seguridad
   - **Activación**: Webhook independiente para auditorías completas
   - **Uso**: Para auditorías de seguridad completas

### Workflow de Explotación

El workflow de explotación se ejecuta automáticamente como parte del workflow de auditoría completa (03-full-audit.json). No dispone de webhook propio ya que está diseñado para ser parte del proceso completo de auditoría.

#### 1. Análisis de Servicios Explotables
- Identificación de servicios con vulnerabilidades conocidas
- Priorización de servicios según riesgo
- Mapeo de servicios a herramientas de explotación
- Análisis de versiones vulnerables
- Detección de configuraciones inseguras

#### 2. Explotación de Servicios Web
- Escaneo con Nuclei para vulnerabilidades web
  - Detección de vulnerabilidades OWASP Top 10
  - Escaneo de vulnerabilidades específicas
  - Análisis de headers de seguridad
- Análisis de directorios con Gobuster
  - Descubrimiento de rutas ocultas
  - Detección de archivos sensibles
  - Análisis de tecnologías web
- Pruebas de inyección SQL con SQLMap
  - Detección de puntos de inyección
  - Explotación de vulnerabilidades SQL
  - Extracción de datos

#### 3. Explotación de Servicios de Red
- Análisis de SMB con CrackMapExec
  - Enumeración de shares
  - Pruebas de autenticación
  - Detección de configuraciones inseguras
- Pruebas de WinRM con Evil-WinRM
  - Verificación de accesos
  - Pruebas de autenticación
  - Análisis de configuraciones
- Escaneo de vulnerabilidades en servicios RPC
  - Detección de servicios expuestos
  - Análisis de permisos
  - Pruebas de acceso

#### 4. Explotación de Servicios de Autenticación
- Pruebas de fuerza bruta
  - SSH, FTP, RDP, etc.
  - Análisis de políticas de contraseñas
  - Detección de cuentas por defecto
- Análisis de políticas de seguridad
  - Configuraciones de bloqueo
  - Políticas de contraseñas
  - Restricciones de acceso

#### 5. Post-Explotación
- Recopilación de información del sistema
  - Configuraciones de red
  - Usuarios y grupos
  - Servicios y procesos
- Análisis de permisos
  - Escalada de privilegios
  - Accesos privilegiados
  - Configuraciones inseguras
- Búsqueda de vectores de persistencia
  - Tareas programadas
  - Servicios de inicio
  - Archivos de configuración

#### 6. Generación de Evidencias
- Capturas de pantalla
  - Vulnerabilidades encontradas
  - Accesos obtenidos
  - Configuraciones inseguras
- Logs de explotación
  - Comandos ejecutados
  - Resultados obtenidos
  - Errores encontrados
- Pruebas de concepto
  - Scripts de explotación
  - Payloads utilizados
  - Vectores de ataque

### Activación de Workflows

1. **Para Escaneo Rápido**:
   ```bash
   curl -X POST http://localhost:5678/webhook/scan-network \
     -H "Content-Type: application/json" \
     -d '{
       "target": "192.168.1.100",
       "intensity": "medium",
       "evasion": true
     }'
   ```

2. **Para Auditoría Completa**:
   ```bash
   curl -X POST http://localhost:5678/webhook/full-audit \
     -H "Content-Type: application/json" \
     -d '{
       "target": "192.168.1.100",
       "intensity": "medium",
       "vulnerability_scan": true,
       "generate_report": true
     }'
   ```

## Mejoras Futuras

### 1. Automatización y Escalabilidad
- Sistema de colas para múltiples objetivos
  - Gestión de prioridades
  - Balanceo de carga
  - Monitoreo de recursos
- Integración con sistemas de gestión
  - Jira, ServiceNow, etc.
  - Ticketing automático
  - Seguimiento de vulnerabilidades
- Escaneos programados
  - Configuración flexible
  - Notificaciones automáticas
  - Historial de escaneos

### 2. Nuevas Funcionalidades
- Análisis de código fuente
  - SAST/DAST integrado
  - Análisis de dependencias
  - Detección de secretos
- Escaneo de contenedores
  - Análisis de imágenes Docker
  - Escaneo de Kubernetes
  - Detección de configuraciones inseguras
- Análisis de aplicaciones móviles
  - Android/iOS
  - Análisis de APIs
  - Detección de vulnerabilidades

### 3. Mejoras en la Explotación
- Framework modular
  - Plugins personalizados
  - Integración de nuevas herramientas
  - Actualización automática
- Exploits personalizados
  - Desarrollo de PoCs
  - Adaptación de exploits
  - Pruebas de concepto
- Técnicas de evasión
  - Bypass de WAF
  - Evasión de IDS/IPS
  - Técnicas de ofuscación

### 4. Mejoras en la Documentación
- Informes multi-formato
  - HTML, PDF, Word
  - Dashboards interactivos
  - Exportación a formatos estándar
- Gestión de conocimiento
  - Base de datos de vulnerabilidades
  - Guías de remediación
  - Mejores prácticas

### 5. Seguridad y Cumplimiento
- Control de acceso
  - RBAC implementado
  - Autenticación MFA
  - Auditoría de acciones
- Gestión de secretos
  - Integración con Vault
  - Rotación de credenciales
  - Cifrado de datos

### 6. Integración y API
- API REST completa
  - Documentación OpenAPI
  - Autenticación OAuth2
  - Rate limiting
- Integración CI/CD
  - Plugins para Jenkins
  - GitHub Actions
  - GitLab CI

### 7. Análisis y Machine Learning
- Análisis predictivo
  - Detección de patrones
  - Predicción de vulnerabilidades
  - Análisis de tendencias
- Clasificación automática
  - Priorización de hallazgos
  - Categorización de vulnerabilidades
  - Recomendaciones inteligentes

### 8. Mejoras en la Usabilidad
- Interfaz web
  - Dashboard interactivo
  - Gestión de escaneos
  - Visualización de resultados
- Configuración asistida
  - Wizards de configuración
  - Plantillas predefinidas
  - Validación de configuraciones

### 9. Optimización de Rendimiento
- Paralelización
  - Escaneos distribuidos
  - Procesamiento en cluster
  - Optimización de recursos
- Caché y almacenamiento
  - Caché inteligente
  - Compresión de datos
  - Gestión de almacenamiento

### 10. Soporte y Mantenimiento
- Actualizaciones
  - Sistema de versionado
  - Actualizaciones automáticas
  - Rollback de cambios
- Soporte
  - Base de conocimiento
  - Sistema de tickets
  - Documentación detallada

## Uso

### 1. Descubrimiento de Puertos

```bash
python3 scripts/port-discovery.py <target> --intensity medium
```

Opciones:
- `--intensity`: low, medium, high, stealth, full
- `--output`: archivo de salida
- `--service-detection`: activar detección de servicios

### 2. Automatización con n8n

1. Iniciar n8n:
```bash
n8n start
```

2. Importar el workflow:
   - Abrir n8n en el navegador (http://localhost:5678)
   - Importar el archivo `workflows/01-recon-enumeration-new.json`

3. Configurar el webhook:
   - El workflow expone un webhook en `/scan-network`
   - Se puede activar con una petición POST

### 3. Generación de Informes

```bash
python3 scripts/generate_report.py <input_file> --output <report_file>
```

## Flujo de Trabajo

1. **Descubrimiento de Puertos**:
   - Escaneo inicial de puertos
   - Detección de versiones de servicios
   - Identificación del sistema operativo

2. **Enumeración de Servicios**:
   - Detección de servicios en puertos abiertos
   - Corrección de identificaciones de servicios
   - Mapeo de servicios según el sistema operativo

3. **Generación de Informes**:
   - Consolidación de resultados
   - Generación de informe en formato HTML/PDF
   - Recomendaciones de seguridad

## Características

- Detección automática de servicios
- Corrección de identificaciones incorrectas
- Integración con herramientas de explotación
- Generación de informes detallados
- Automatización mediante n8n
- Soporte para múltiples objetivos
- Configuración flexible de escaneos

## Contribuir

1. Fork el repositorio
2. Crea una rama para tu feature (`git checkout -b feature/AmazingFeature`)
3. Commit tus cambios (`git commit -m 'Add some AmazingFeature'`)
4. Push a la rama (`git push origin feature/AmazingFeature`)
5. Abre un Pull Request

## Licencia

Este proyecto está licenciado bajo la Licencia MIT - ver el archivo [LICENSE](LICENSE) para más detalles.

## Contacto

Tu Nombre - [@tutwitter](https://twitter.com/tutwitter)

Link del Proyecto: [https://github.com/tu-usuario/kali-security-tools](https://github.com/tu-usuario/kali-security-tools) 