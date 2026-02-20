# 📦 Panel de Control de Minecraft (Docker + Node.js)

Un gestor ligero y potente para administrar servidores de **Minecraft** usando **Docker** y una interfaz web moderna.

Este proyecto permite crear, iniciar, detener y administrar múltiples servidores desde el navegador, con monitoreo en tiempo real, gestión de archivos y soporte para diferentes tipos de servidor.

---

## 🚀 ✨ Características

- 🐳 Cada servidor corre en su propio contenedor Docker
- 🌐 Interfaz web con Express + Socket.io
- ⚡ Consola en tiempo real
- 📊 Monitorización de CPU y RAM
- 📂 Gestión de archivos (mundos, configuraciones, logs)
- 📦 Descarga y creación de backups
- 🔌 Soporte para:
  - Paper
  - Purpur
  - Fabric
  - Forge
  - Vanilla
  - Velocity
  - BungeeCord
- 👥 Lista de jugadores conectados

---

## 🧰 Requisitos

Antes de usar el panel necesitas:

- Node.js >= 18
- Docker instalado y en ejecución
- Permisos para ejecutar Docker desde tu usuario

Verifica Docker con:

```bash
docker --version
```

---

## 📥 Instalación

Clona el repositorio:

```bash
git clone https://github.com/deny3012/servidor-de-minecraft.git
cd servidor-de-minecraft
```

Instala dependencias:

```bash
npm install
```

---

## ▶️ Uso

Iniciar normalmente:

```bash
node server-manager.js
```

Iniciar en modo HTTP:

```bash
node server-manager.js --http
```

Luego abre en tu navegador:

```
https://localhost:3000
```

*(Ajusta el puerto si lo modificaste en el código)*

---

## 📁 Estructura del Proyecto

```
.
├── server-manager.js
├── index.html
├── index.js
├── package.json
├── package-lock.json
└── README.md
```

---

## 🏗 Arquitectura General

1. El usuario interactúa desde la interfaz web.
2. Express recibe las solicitudes.
3. El backend gestiona contenedores Docker.
4. Socket.io actualiza información en tiempo real.
5. Los datos del servidor se gestionan mediante utilidades de Minecraft y lectura NBT.

---

## 🔐 Seguridad

Este panel está pensado para uso local.

Si lo expones a internet, considera:

- Añadir autenticación
- Usar HTTPS válido
- Configurar firewall
- Limitar accesos por IP

---

## 🛠 Futuras Mejoras

- Sistema de autenticación
- Gestión avanzada de roles
- Editor de archivos desde la web
- Logs más detallados
- Sistema de plugins extendido
- Dashboard con métricas históricas

---

## 📌 Objetivo del Proyecto

Simplificar la administración de servidores Minecraft locales mediante una solución ligera, modular y basada en Docker.

---

## 📜 Licencia

MIT