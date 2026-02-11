# 🎮 Panel de Control de Minecraft (Docker + Node.js)

![NodeJS](https://img.shields.io/badge/node.js-6DA55F?style=for-the-badge&logo=node.js&logoColor=white)
![Docker](https://img.shields.io/badge/docker-%230db7ed.svg?style=for-the-badge&logo=docker&logoColor=white)
![Status](https://img.shields.io/badge/status-activo-success.svg?style=for-the-badge)

Gestor de servidores de Minecraft ligero, potente y auto-hospedado. Diseñado para correr en tu propia máquina usando Docker, ofreciendo una interfaz web moderna para gestionar múltiples servidores Java y Bedrock.

## ✨ Características Principales

*   **🚀 Creación Instantánea:** Soporte para Paper, Purpur, Fabric, Forge, Vanilla, Velocity, BungeeCord y más.
*   **🐳 Aislamiento Docker:** Cada servidor corre en su propio contenedor para máxima estabilidad y seguridad.
*   **🔌 Puertos Inteligentes:** Detección automática de puertos libres. Soporte dual Java (TCP) + Bedrock (UDP/Geyser).
*   **📊 Monitorización en Vivo:** Gráficas de CPU y RAM en tiempo real vía WebSockets.
*   **💻 Consola Web:** Terminal interactiva con historial de logs.
*   **📂 Gestor de Archivos:**
    *   Editor de configuración (properties, yml, json) con resaltado de sintaxis.
    *   Subida de archivos (Drag & Drop).
    *   Descarga de backups y logs.
*   **👥 Gestión Avanzada de Jugadores:**
    *   Lista de jugadores online.
    *   **Visor de Inventario:** Mira el inventario, armadura y EnderChest de los jugadores (incluso offline) leyendo archivos NBT.
    *   Gestión de Whitelist, OP y Baneos.
*   **🛡️ Seguridad:**
    *   Autenticación básica.
    *   Lista blanca de IPs para restringir el acceso al panel.
    *   Soporte HTTPS (SSL autofirmado automático).
*   **🧩 Sistema de Plugins:** Extensible mediante scripts JS en backend y frontend.

## 💻 Compatibilidad

| Característica | Linux 🐧 | macOS 🍎 | Windows 🪟 |
| :--- | :---: | :---: | :---: |
| **Gestión de Servidores (Docker)** | ✅ | ✅ | ✅ |
| **Autenticación Sistema (PAM)** | ✅ | ❌ | ❌ |
| **Autenticación Archivo JSON** | ✅ | ✅ | ✅ |
| **HTTPS (SSL Automático)** | ✅ | ✅ | ⚠️ (Requiere OpenSSL) |

## � Requisitos

1.  **Node.js** (v18+): [Descargar](https://nodejs.org/). Se requiere v18 o superior por el uso de la API `fetch` nativa.
2.  **Docker Desktop** o **Docker Engine**: [Descargar](https://www.docker.com/products/docker-desktop/).
    > **Importante:** Docker debe estar ejecutándose antes de iniciar el panel.

3.  **(Opcional) OpenSSL**: Necesario para la generación automática de certificados HTTPS. Viene preinstalado en la mayoría de sistemas Linux y macOS. Si no está presente, el panel se iniciará en modo HTTP.

4.  **(Opcional, solo Linux) Herramientas de Compilación**: Para que la autenticación con usuarios del sistema funcione, necesitarás las herramientas para compilar módulos nativos de Node.js.
    *   En Debian/Ubuntu: `sudo apt install build-essential libpam-dev`
    *   En Arch Linux: `sudo pacman -S base-devel pam`

## 🛠️ Instalación

1.  Clona el repositorio o descarga el código.
2.  Abre una terminal en la carpeta del proyecto.
3.  Instala las dependencias:
    ```bash
    npm install
    ```

## 🚀 Cómo Usar

1.  **Iniciar el Panel:**
    ```bash
    node server-manager.js
    ```
    *Para modo HTTP (sin SSL):* `node server-manager.js --http`

2.  **Acceder:**
    *   Abre `https://localhost:3000` en tu navegador.
    *   **Credenciales:** Al primer inicio, mira la consola para ver la contraseña generada en `panel-auth.json`.

## 📂 Estructura del Proyecto

*   `servers/`: Datos persistentes de los servidores (mundos, configs).
*   `backups/`: Zips generados manualmente.
*   `plugins/`: Plugins del backend (Node.js).
*   `web-plugins/`: Plugins del frontend (JS cliente).
*   `server-manager.js`: Servidor principal.
*   `index.html`: Interfaz de usuario.

## 🧩 Desarrollo de Plugins Web

El panel permite cargar scripts personalizados en el navegador (Frontend) automáticamente.

**Pasos para crear un plugin web:**
1.  Navega a la carpeta `web-plugins/`.
2.  Crea una nueva carpeta con el nombre de tu plugin (ej: `mejoras-visuales`).
3.  Dentro de esa carpeta, crea un archivo `.js` (ej: `main.js`).
4.  El panel inyectará este script automáticamente en el navegador.

**Estructura de archivos:**
```text
web-plugins/
└── nombre-del-plugin/
    └── script.js
```

## ❓ Solución de Problemas

*   **Error de Docker:** Verifica que Docker Desktop esté abierto.
*   **Advertencia de Seguridad:** Al usar certificados autofirmados, el navegador avisará que "La conexión no es privada". Debes dar clic en "Avanzado" > "Continuar a localhost".
*   **Permisos en Linux:** Si tienes errores de escritura, asegúrate de que tu usuario tenga permisos sobre el socket de Docker (`sudo usermod -aG docker $USER`).

---
Creado con ❤️ para facilitar la administración de servidores en casa.
