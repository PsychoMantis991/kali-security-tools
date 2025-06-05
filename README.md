# Kali Security Tools

Herramientas de seguridad para Kali Linux que automatizan tareas de enumeración, pivoting y movimiento lateral.

## Características

- Enumeración de usuarios y Active Directory
- Técnicas sigilosas para evadir detección
- Enumeración de servicios
- Pivoting de red
- Movimiento lateral inteligente
- Integración con Metasploit Framework

## Requisitos

- Kali Linux
- Python 3.8+
- Metasploit Framework
- pymetasploit3

## Instalación

1. Clonar el repositorio:
```bash
git clone https://github.com/tu-usuario/kali-security-tools.git
cd kali-security-tools
```

2. Instalar dependencias:
```bash
pip install -r requirements.txt
```

3. Configurar Metasploit:
```bash
msfconsole
msf6 > load msgrpc ServerHost=127.0.0.1 ServerPort=55553 User=msf Pass=password
```

4. Editar la configuración:
```bash
nano config/config.json
```

## Uso

### Enumeración básica

```bash
python scripts/enumerate.py 192.168.1.100
```

### Enumeración con credenciales

```bash
python scripts/enumerate.py 192.168.1.100 --username admin --password password --domain example.com
```

### Modos de enumeración

- `users`: Enumeración de usuarios
- `ad`: Enumeración de Active Directory
- `services`: Enumeración de servicios
- `pivot`: Pivoting de red
- `lateral`: Movimiento lateral
- `all`: Todos los modos (por defecto)

Ejemplo:
```bash
python scripts/enumerate.py 192.168.1.100 --mode services
```

### Técnicas sigilosas

```bash
python scripts/enumerate.py 192.168.1.100 --stealth
```

### Guardar resultados

```bash
python scripts/enumerate.py 192.168.1.100 --output resultados.json
```

## Estructura del proyecto

```
kali-security-tools/
├── config/
│   └── config.json
├── scripts/
│   ├── enumerate.py
│   └── exploit/
│       ├── user_enumeration.py
│       ├── active_directory.py
│       ├── stealth_techniques.py
│       ├── service_enumeration.py
│       ├── network_pivoting.py
│       └── lateral_movement.py
├── temp/
├── README.md
└── requirements.txt
```

## Configuración

El archivo `config/config.json` contiene la configuración del proyecto:

```json
{
    "metasploit": {
        "host": "127.0.0.1",
        "port": 55553,
        "user": "msf",
        "password": "password"
    },
    "stealth": {
        "enabled": true,
        "techniques": [
            "timing",
            "fragmentation",
            "encryption"
        ]
    },
    "pivoting": {
        "enabled": true,
        "methods": [
            "ssh",
            "socks",
            "port_forwarding"
        ]
    }
}
```

## Contribuir

1. Fork el repositorio
2. Crear una rama para tu feature (`git checkout -b feature/AmazingFeature`)
3. Commit tus cambios (`git commit -m 'Add some AmazingFeature'`)
4. Push a la rama (`git push origin feature/AmazingFeature`)
5. Abrir un Pull Request

## Licencia

Este proyecto está licenciado bajo la Licencia MIT - ver el archivo [LICENSE](LICENSE) para más detalles.

## Advertencia

Esta herramienta está diseñada únicamente para pruebas de seguridad autorizadas. El uso de esta herramienta contra sistemas sin autorización es ilegal y no ético. El autor no se hace responsable del uso indebido de esta herramienta. 