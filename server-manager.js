const Docker = require('dockerode');
const docker = new Docker(); // En Linux detecta automáticamente /var/run/docker.sock
const fs = require('fs');
const path = require('path');
const os = require('os');
const express = require('express');
const http = require('http');
const https = require('https');
const { execSync } = require('child_process');
const { Server } = require("socket.io");
const multer = require('multer');
let pam;
try {
    if (process.env.CODESPACES === 'true') throw new Error('Codespaces detectado: Usando autenticación por archivo');
    pam = require('node-linux-pam');
} catch (e) {
    console.log('AVISO: Módulo PAM no cargado. Usando modo desarrollo (admin/admin).');
}
const util = require('minecraft-server-util');
const archiver = require('archiver');
const nbt = require('prismarine-nbt');

const app = express();

// --- SEGURIDAD: IP Whitelist (Lista Blanca) ---
const WHITELIST_FILE = path.join(__dirname, 'panel-whitelist.json');

function getWhitelistedIPs() {
    if (!fs.existsSync(WHITELIST_FILE)) return [];
    try { return JSON.parse(fs.readFileSync(WHITELIST_FILE, 'utf8')); } catch (e) { return []; }
}

app.use((req, res, next) => {
    const whitelist = getWhitelistedIPs();
    if (whitelist.length === 0) return next(); // Lista vacía = Protección desactivada

    let clientIp = req.ip || req.socket.remoteAddress;
    if (clientIp && clientIp.startsWith('::ffff:')) clientIp = clientIp.substr(7);
    
    // Siempre permitir localhost para no bloquearse a uno mismo en la máquina host
    if (clientIp === '127.0.0.1' || clientIp === '::1') return next();

    if (whitelist.includes(clientIp)) return next();

    logActivity(`Bloqueado acceso al panel desde IP no autorizada: ${clientIp}`);
    res.status(403).send(`<h1>Acceso Denegado</h1><p>Tu IP (${clientIp}) no está autorizada para ver este panel.</p>`);
});

// Configuración SSL (HTTPS)
const keyPath = path.join(__dirname, 'server.key');
const certPath = path.join(__dirname, 'server.cert');

// Verificar si se solicitó modo HTTP explícito (útil para túneles como Playit/Ngrok)
const useHttp = process.argv.includes('--http') || process.env.CODESPACES === 'true';

// Intentar generar certificados si no existen (requiere openssl, común en Linux)
if (!useHttp && (!fs.existsSync(keyPath) || !fs.existsSync(certPath))) {
    try {
        console.log('Generando certificados SSL autofirmados...');
        execSync(`openssl req -nodes -new -x509 -keyout "${keyPath}" -out "${certPath}" -days 365 -subj "/CN=MinecraftPanel"`);
    } catch (e) {
        console.log('Aviso: No se pudo generar SSL automáticamente. Iniciando en HTTP.');
    }
}

const isHttps = !useHttp && fs.existsSync(keyPath) && fs.existsSync(certPath);
const server = isHttps ? https.createServer({ key: fs.readFileSync(keyPath), cert: fs.readFileSync(certPath) }, app) : http.createServer(app);

const io = new Server(server, {
    cors: { origin: "*", methods: ["GET", "POST"] }
});

// Configuración
const PORT = 3000;
const MINECRAFT_IMAGE = 'itzg/minecraft-server';

// --- SISTEMA DE LOGS ---
const LOG_FILE = path.join(__dirname, 'panel.log');

function logActivity(message) {
    const timestamp = new Date().toLocaleString();
    const logEntry = `[${timestamp}] ${message}`;
    console.log(logEntry); // Mostrar en consola
    // Guardar en archivo (append)
    try { fs.appendFileSync(LOG_FILE, logEntry + '\n'); } catch (e) {}
}

// --- SEGURIDAD: Credenciales Configurables ---
const AUTH_FILE = path.join(__dirname, 'panel-auth.json');
let authConfig = { user: 'admin', pass: 'admin' };

// Cargar o Generar credenciales al iniciar
if (fs.existsSync(AUTH_FILE)) {
    try {
        authConfig = JSON.parse(fs.readFileSync(AUTH_FILE, 'utf8'));
    } catch (e) { console.error('Error leyendo panel-auth.json, usando defaults.'); }
} else {
    try {
        const currentUser = os.userInfo().username || 'admin';
        const randomPass = Math.random().toString(36).slice(-8); // Generar contraseña aleatoria
        authConfig = { user: currentUser, pass: randomPass };
        fs.writeFileSync(AUTH_FILE, JSON.stringify(authConfig, null, 2));
        console.log('\n====================================================');
        console.log('🔐 SEGURIDAD: Se han generado nuevas credenciales');
        console.log(`👤 Usuario:    ${authConfig.user}`);
        console.log(`🔑 Contraseña: ${authConfig.pass}`);
        console.log('📝 Puedes cambiarlas editando el archivo: panel-auth.json');
        console.log('====================================================\n');
    } catch (e) {}
}

// --- SEGURIDAD: Autenticación Básica ---
app.use((req, res, next) => {
    const b64auth = (req.headers.authorization || '').split(' ')[1] || '';
    const [login, password] = Buffer.from(b64auth, 'base64').toString().split(':');

    if (!login || !password) {
        res.set('WWW-Authenticate', 'Basic realm="Panel Minecraft Protegido"');
        return res.status(401).send('Autenticación requerida. Recarga la página.');
    }

    // Autenticar contra el sistema Linux usando PAM
    if (pam) {
        pam.authenticate(login, password, (err) => {
            if (err) {
                // Si hay error, la contraseña es incorrecta o el usuario no existe
                logActivity(`Intento de acceso fallido: Usuario '${login}'`);
                res.set('WWW-Authenticate', 'Basic realm="Panel Minecraft Protegido"');
                return res.status(401).send('Credenciales incorrectas.');
            }
            return next(); // Credenciales correctas
        });
    } else {
        // Fallback usando configuración local (panel-auth.json)
        if (login === authConfig.user && password === authConfig.pass) {
            return next();
        }
        res.set('WWW-Authenticate', 'Basic realm="Panel Minecraft Protegido"');
        return res.status(401).send('Credenciales incorrectas.');
    }
});

app.use(express.json());

// Servir index.html directamente desde la raíz
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Habilitar CORS
app.use((req, res, next) => {
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
    next();
});

// Configuración de subida de archivos (Multer)
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        const serverRoot = path.join(__dirname, 'servers', req.params.serverName);
        let uploadPath = serverRoot;
        
        // Soporte para subir a subcarpetas
        if (req.query.path) {
            const safePath = req.query.path.replace(/\.\./g, ''); // Seguridad básica
            uploadPath = path.join(serverRoot, safePath);
        }

        if (!uploadPath.startsWith(serverRoot)) return cb(new Error('Acceso denegado'), null);
        if (!fs.existsSync(uploadPath)) return cb(new Error('El directorio no existe'), null);
        
        cb(null, uploadPath);
    },
    filename: function (req, file, cb) {
        cb(null, file.originalname); // Mantener nombre original
    }
});
const upload = multer({ storage: storage });

/**
 * Crea un nuevo servidor
 */
app.post('/create-server', async (req, res) => {
    const { serverName, ramLimit, port, bedrockPort, serverType, serverVersion, loaderVersion } = req.body;
    
    logActivity(`Creando servidor: ${serverName} (${serverType} ${serverVersion})`);

    // Ruta absoluta en Linux
    const serverPath = path.join(__dirname, 'servers', serverName);
    
    if (!fs.existsSync(serverPath)) {
        fs.mkdirSync(serverPath, { recursive: true });
        // IMPORTANTE: Dar permisos 777 para evitar problemas de escritura con Docker en Linux
        fs.chmodSync(serverPath, '777'); 
    }

    // Configurar variables de entorno
    const envVars = [
        'EULA=TRUE',
        `VERSION=${serverVersion || 'LATEST'}`,
        `TYPE=${serverType || 'PAPER'}`,
        `MEMORY=${ramLimit || '1G'}`,
        `SERVER_PORT=${port}`
    ];
    // Si es Fabric y tenemos versión del loader, la agregamos
    if (serverType === 'FABRIC' && loaderVersion) envVars.push(`FABRIC_LOADER_VERSION=${loaderVersion}`);

    // Preparar configuración de puertos (Evitar conflictos UDP)
    const portBindings = {
        [`${port}/tcp`]: [{ HostPort: String(port) }]
    };

    const bPort = String(bedrockPort || '19132');
    const jPort = String(port);

    if (jPort !== bPort) {
        // Si son puertos distintos, activamos todo: Query (Java) y Geyser (Bedrock)
        portBindings[`${jPort}/udp`] = [{ HostPort: jPort }];
        portBindings['19132/udp'] = [{ HostPort: bPort }];
    } else {
        // Si el usuario eligió el MISMO puerto para ambos, priorizamos Bedrock en UDP
        // (Docker fallaría si intentamos mapear el mismo puerto UDP a dos servicios distintos)
        portBindings['19132/udp'] = [{ HostPort: bPort }];
    }

    try {
        // Verificar si la imagen existe, si no, descargarla (Evita error 404)
        const images = await docker.listImages();
        const imageExists = images.some(img => img.RepoTags && img.RepoTags.some(t => t.startsWith(MINECRAFT_IMAGE)));
        
        if (!imageExists) {
            logActivity(`⚠️ Imagen Docker no encontrada. Descargando ${MINECRAFT_IMAGE}... (Esto puede tardar)`);
            await new Promise((resolve, reject) => {
                docker.pull(MINECRAFT_IMAGE, (err, stream) => {
                    if (err) return reject(err);
                    docker.modem.followProgress(stream, (err, res) => err ? reject(err) : resolve(res));
                });
            });
            logActivity(`✅ Imagen descargada.`);
        }

        const container = await docker.createContainer({
            Image: MINECRAFT_IMAGE,
            name: `mc-${serverName}`,
            Env: envVars,
            ExposedPorts: {
                [`${port}/tcp`]: {},
                [`${port}/udp`]: {},     // Para Query
                '19132/udp': {}          // Puerto interno de Geyser
            },
            HostConfig: {
                PortBindings: portBindings,
                Binds: [`${serverPath}:/data`],
                Memory: 1024 * 1024 * 1024 * (parseInt(ramLimit) || 1),
                RestartPolicy: { Name: 'unless-stopped' } // Reiniciar automáticamente si la laptop se reinicia
            },
            AttachStdin: true,
            AttachStdout: true,
            AttachStderr: true,
            Tty: true,
            OpenStdin: true
        });

        // Iniciar automáticamente para que comience la descarga de archivos
        try {
            await container.start();
        } catch (e) {
            // Ignorar error si ya se inició (evita falsos positivos)
            if (e.statusCode != 304 && !e.message.includes('already started') && !e.message.includes('304')) throw e;
        }
        logActivity(`Servidor creado e iniciado: ${serverName} (ID: ${container.id.substring(0, 12)})`);
        res.json({ message: 'Servidor creado e iniciando descarga...', id: container.id });
    } catch (error) {
        logActivity(`Error creando servidor ${serverName}: ${error.message}`);
        res.status(500).json({ error: error.message });
    }
});

/**
 * Iniciar Servidor
 */
app.post('/start-server/:id', async (req, res) => {
    try {
        const container = docker.getContainer(req.params.id);
        await container.start();
        logActivity(`Servidor iniciado: ${req.params.id.substring(0, 12)}`);
        res.json({ message: 'Servidor iniciado' });
    } catch (error) {
        // Si ya está encendido, no lo tratamos como error
        if (error.statusCode == 304 || (error.message && (error.message.includes('already started') || error.message.includes('304')))) {
            return res.json({ message: 'El servidor ya está en línea.' });
        }
        logActivity(`Error iniciando servidor: ${error.message}`);
        res.status(500).json({ error: error.message });
    }
});

/**
 * Actualizar Servidor (Recrear contenedor con nueva versión)
 */
app.post('/update-server/:id', async (req, res) => {
    const { version, type } = req.body;
    try {
        const container = docker.getContainer(req.params.id);
        const info = await container.inspect();
        const name = info.Name.replace('/', ''); // Quitar slash inicial

        // 1. Obtener configuración actual
        const env = info.Config.Env || [];
        const binds = info.HostConfig.Binds || [];
        const portBindings = info.HostConfig.PortBindings || {};
        const memory = info.HostConfig.Memory || 0;
        const restartPolicy = info.HostConfig.RestartPolicy || { Name: 'unless-stopped' };
        
        // 2. Preparar nuevo entorno
        // Filtramos VERSION, TYPE y FORCE_REDOWNLOAD anteriores para poner los nuevos
        const newEnv = env.filter(e => 
            !e.startsWith('VERSION=') && 
            !e.startsWith('TYPE=') &&
            !e.startsWith('FORCE_REDOWNLOAD=')
        );
        
        newEnv.push(`VERSION=${version}`);
        if (type) newEnv.push(`TYPE=${type}`);
        newEnv.push('FORCE_REDOWNLOAD=true'); // Forzar descarga del nuevo jar

        logActivity(`Actualizando servidor ${name} a versión ${version} (${type || 'Mismo Tipo'})`);

        // 3. Detener y eliminar contenedor viejo (Los archivos en /data NO se borran)
        if (info.State.Running) {
            await container.stop();
        }
        await container.remove();

        // 4. Crear nuevo contenedor con la config actualizada
        const newContainer = await docker.createContainer({
            Image: info.Config.Image,
            name: name,
            Env: newEnv,
            ExposedPorts: info.Config.ExposedPorts,
            HostConfig: {
                Binds: binds,
                PortBindings: portBindings,
                Memory: memory,
                RestartPolicy: restartPolicy
            },
            AttachStdin: true,
            AttachStdout: true,
            AttachStderr: true,
            Tty: true,
            OpenStdin: true
        });

        // 5. Iniciar para que empiece la descarga
        await newContainer.start();

        res.json({ message: 'Servidor actualizado. Iniciando descarga de nueva versión...' });

    } catch (error) {
        logActivity(`Error actualizando servidor: ${error.message}`);
        res.status(500).json({ error: error.message });
    }
});

/**
 * Detener Servidor
 */
app.post('/stop-server/:id', async (req, res) => {
    try {
        const container = docker.getContainer(req.params.id);
        await container.stop();
        logActivity(`Servidor detenido: ${req.params.id.substring(0, 12)}`);
        res.json({ message: 'Servidor detenido' });
    } catch (error) {
        logActivity(`Error deteniendo servidor: ${error.message}`);
        res.status(500).json({ error: error.message });
    }
});

/**
 * Reiniciar Servidor
 */
app.post('/restart-server/:id', async (req, res) => {
    try {
        const container = docker.getContainer(req.params.id);
        await container.restart();
        logActivity(`Servidor reiniciado: ${req.params.id.substring(0, 12)}`);
        res.json({ message: 'Servidor reiniciado' });
    } catch (error) {
        logActivity(`Error reiniciando servidor: ${error.message}`);
        res.status(500).json({ error: error.message });
    }
});

/**
 * Matar Servidor (Kill)
 */
app.post('/kill-server/:id', async (req, res) => {
    try {
        const container = docker.getContainer(req.params.id);
        await container.kill();
        logActivity(`Servidor FORZADO (Kill): ${req.params.id.substring(0, 12)}`);
        res.json({ message: 'Proceso del servidor eliminado (Kill)' });
    } catch (error) {
        logActivity(`Error matando servidor: ${error.message}`);
        res.status(500).json({ error: error.message });
    }
});

/**
 * Eliminar Servidor Completo
 */
app.delete('/delete-server/:id', async (req, res) => {
    try {
        const container = docker.getContainer(req.params.id);
        
        // 1. Obtener ruta de los archivos antes de borrar el contenedor
        const info = await container.inspect();
        const mount = info.Mounts.find(m => m.Destination === '/data');
        
        // 2. Eliminar contenedor (force: true lo detiene si está corriendo)
        await container.remove({ force: true });

        // 3. Eliminar carpeta de archivos
        if (mount && mount.Source && fs.existsSync(mount.Source)) {
            fs.rmSync(mount.Source, { recursive: true, force: true });
        }

        logActivity(`Servidor ELIMINADO: ${req.params.id.substring(0, 12)}`);
        res.json({ message: 'Servidor y archivos eliminados correctamente' });
    } catch (error) {
        logActivity(`Error eliminando servidor: ${error.message}`);
        res.status(500).json({ error: error.message });
    }
});

/**
 * Descargar Logs
 */
app.get('/download-logs/:id', async (req, res) => {
    try {
        const container = docker.getContainer(req.params.id);
        const logs = await container.logs({
            stdout: true, stderr: true, timestamps: true
        });
        
        res.setHeader('Content-Disposition', `attachment; filename="logs-${req.params.id}.txt"`);
        res.setHeader('Content-Type', 'text/plain');
        res.send(logs);
    } catch (error) {
        res.status(500).send('Error obteniendo logs: ' + error.message);
    }
});

// Listar archivos del servidor
app.get('/files/:serverName', (req, res) => {
    const serverRoot = path.join(__dirname, 'servers', req.params.serverName);
    const subPath = req.query.path ? req.query.path.replace(/\.\./g, '') : '';
    const targetPath = path.join(serverRoot, subPath);

    if (!targetPath.startsWith(serverRoot)) return res.status(403).json({ error: 'Acceso denegado' });
    if (!fs.existsSync(targetPath)) return res.json([]);
    
    fs.readdir(targetPath, { withFileTypes: true }, (err, files) => {
        if (err) return res.status(500).json({ error: err.message });
        const fileList = files.map(f => ({
            name: f.name,
            isDirectory: f.isDirectory(),
            size: f.isDirectory() ? '-' : fs.statSync(path.join(targetPath, f.name)).size
        }));
        res.json(fileList);
    });
});

// Subir archivos (Drag & Drop)
app.post('/upload/:serverName', upload.array('files'), (req, res) => {
    res.json({ message: 'Archivos subidos correctamente' });
});

// Eliminar archivos o carpetas
app.delete('/delete-file/:serverName', (req, res) => {
    const { fileName } = req.body;
    const serverPath = path.join(__dirname, 'servers', req.params.serverName);
    const filePath = path.join(serverPath, fileName);

    // Seguridad básica: evitar borrar archivos fuera de la carpeta del servidor
    if (!filePath.startsWith(serverPath)) {
        return res.status(403).json({ error: 'Acceso denegado' });
    }

    try {
        // rmSync elimina archivos o carpetas recursivamente
        if (fs.existsSync(filePath)) fs.rmSync(filePath, { recursive: true, force: true });
        res.json({ message: 'Elemento eliminado' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Descargar archivo individual
app.get('/download-file/:serverName', (req, res) => {
    const { fileName } = req.query;
    const serverPath = path.join(__dirname, 'servers', req.params.serverName);
    const filePath = path.join(serverPath, fileName);

    if (!filePath.startsWith(serverPath)) return res.status(403).send('Acceso denegado');
    if (!fs.existsSync(filePath)) return res.status(404).send('Archivo no encontrado');

    res.download(filePath);
});

// Leer contenido de archivo
app.get('/read-file/:serverName', (req, res) => {
    const { fileName } = req.query;
    const serverPath = path.join(__dirname, 'servers', req.params.serverName);
    const filePath = path.join(serverPath, fileName);

    if (!filePath.startsWith(serverPath)) return res.status(403).json({ error: 'Acceso denegado' });
    if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'Archivo no encontrado' });

    try {
        const content = fs.readFileSync(filePath, 'utf8');
        res.json({ content });
    } catch (error) {
        res.status(500).json({ error: 'Error al leer archivo' });
    }
});

// Guardar contenido de archivo
app.post('/save-file/:serverName', (req, res) => {
    const { fileName, content } = req.body;
    const serverPath = path.join(__dirname, 'servers', req.params.serverName);
    const filePath = path.join(serverPath, fileName);

    if (!filePath.startsWith(serverPath)) return res.status(403).json({ error: 'Acceso denegado' });

    try {
        fs.writeFileSync(filePath, content, 'utf8');
        res.json({ message: 'Archivo guardado correctamente' });
    } catch (error) {
        res.status(500).json({ error: 'Error al guardar archivo' });
    }
});

// --- ENDPOINTS SEGURIDAD PANEL ---
app.get('/panel-whitelist', (req, res) => {
    res.json(getWhitelistedIPs());
});

app.post('/panel-whitelist', (req, res) => {
    const { ip } = req.body;
    if (!ip) return res.status(400).json({ error: 'IP inválida' });
    
    const list = getWhitelistedIPs();
    if (!list.includes(ip)) {
        list.push(ip);
        fs.writeFileSync(WHITELIST_FILE, JSON.stringify(list, null, 2));
    }
    logActivity(`IP añadida a whitelist del panel: ${ip}`);
    res.json({ message: 'IP añadida', list });
});

app.delete('/panel-whitelist', (req, res) => {
    const { ip } = req.body;
    let list = getWhitelistedIPs();
    const initialLength = list.length;
    list = list.filter(i => i !== ip);
    
    if (list.length !== initialLength) {
        if (list.length === 0 && fs.existsSync(WHITELIST_FILE)) {
            fs.unlinkSync(WHITELIST_FILE); // Borrar archivo si está vacío para desactivar
        } else {
            fs.writeFileSync(WHITELIST_FILE, JSON.stringify(list, null, 2));
        }
    }
    logActivity(`IP eliminada de whitelist del panel: ${ip}`);
    res.json({ message: 'IP eliminada', list });
});

app.get('/my-ip', (req, res) => {
    let clientIp = req.ip || req.socket.remoteAddress;
    if (clientIp && clientIp.startsWith('::ffff:')) clientIp = clientIp.substr(7);
    res.json({ ip: clientIp });
});

// --- NUEVO: Detección automática de puertos libres ---
app.get('/next-ports', async (req, res) => {
    try {
        const containers = await docker.listContainers({ all: true });
        const usedTcp = new Set();
        const usedUdp = new Set();

        // 1. Escanear todos los contenedores para ver qué puertos usan
        for (const c of containers) {
            try {
                const container = docker.getContainer(c.Id);
                const info = await container.inspect();
                const bindings = info.HostConfig.PortBindings || {};
                
                for (const key in bindings) {
                    const [port, proto] = key.split('/'); // ej: "25565/tcp"
                    if (bindings[key]) {
                        bindings[key].forEach(b => {
                            const hostPort = parseInt(b.HostPort);
                            if (proto === 'tcp') usedTcp.add(hostPort);
                            if (proto === 'udp') usedUdp.add(hostPort);
                        });
                    }
                }
            } catch (e) {}
        }

        // 2. Buscar el siguiente libre empezando por los defaults
        let tcp = 25565;
        while (usedTcp.has(tcp)) tcp++;

        let udp = 19132;
        while (usedUdp.has(udp)) udp++;

        res.json({ tcp, udp });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Listar servidores creados
app.get('/list-servers', async (req, res) => {
    try {
        const containers = await docker.listContainers({ all: true });
        
        // Procesamos cada contenedor para obtener su puerto real
        const serverPromises = containers
            .filter(c => c.Names.some(n => n.startsWith('/mc-')))
            .map(async c => {
                let port = null;
                let bedrockPort = '19132'; // Default

                // 1. Intentar método antiguo (Bridge) por si tienes servidores viejos
                const portInfo = (c.Ports || []).find(p => p.PrivatePort === 25565);
                if (portInfo) {
                    port = portInfo.PublicPort;
                } else {
                    // 2. Método nuevo (Host): Inspeccionar variable de entorno SERVER_PORT
                    try {
                        const container = docker.getContainer(c.Id);
                        const info = await container.inspect();
                        const env = info.Config.Env || [];
                        const portVar = env.find(e => e.startsWith('SERVER_PORT='));
                        if (portVar) port = portVar.split('=')[1];

                        // Detectar puerto Bedrock mapeado (UDP)
                        const bindings = info.HostConfig.PortBindings;
                        if (bindings && bindings['19132/udp']) {
                            bedrockPort = bindings['19132/udp'][0].HostPort;
                        }
                    } catch (e) {}
                }

                return {
                    id: c.Id,
                    name: c.Names[0].replace('/mc-', ''),
                    status: c.State,
                    port: port || '25565',
                    bedrockPort: bedrockPort
                };
            });

        const servers = await Promise.all(serverPromises);
        res.json(servers);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Obtener estado y jugadores del servidor
app.get('/server-status/:port', async (req, res) => {
    const port = parseInt(req.params.port);
    if (!port) return res.json({ online: false });

    try {
        // Consulta el estado del servidor localmente
        const result = await util.status('localhost', port, { timeout: 1000 });
        res.json({
            online: true,
            players: result.players.sample || [], // Lista de nombres
            count: result.players.online,
            max: result.players.max
        });
    } catch (e) {
        res.json({ online: false });
    }
});

// Obtener detalles del jugador (Inventario, EnderChest, Stats)
app.get('/player-details/:serverName/:playerName', async (req, res) => {
    const { serverName, playerName } = req.params;
    const serverPath = path.join(__dirname, 'servers', serverName);
    
    try {
        // 1. Obtener UUID desde usercache.json
        const cachePath = path.join(serverPath, 'usercache.json');
        if (!fs.existsSync(cachePath)) return res.status(404).json({ error: 'Caché de usuarios no encontrado' });
        
        const cache = JSON.parse(fs.readFileSync(cachePath, 'utf8'));
        const user = cache.find(u => u.name.toLowerCase() === playerName.toLowerCase());
        
        if (!user) return res.status(404).json({ error: 'Jugador no encontrado en caché' });
        const uuid = user.uuid;

        // 2. Leer Player Data (NBT) - Inventario y EnderChest
        // Nota: Asumimos que el mundo se llama 'world'. Si cambiaste el level-name, ajusta esto.
        // Intentamos leer server.properties para ser más robustos
        let levelName = 'world';
        try {
            const props = fs.readFileSync(path.join(serverPath, 'server.properties'), 'utf8');
            const match = props.match(/level-name=(.*)/);
            if (match) levelName = match[1].trim();
        } catch (e) {}

        const playerDataPath = path.join(serverPath, levelName, 'playerdata', `${uuid}.dat`);
        let inventory = [];
        let enderChest = [];
        let vitals = { health: 20, foodLevel: 20, foodSaturation: 5, xpLevel: 0, xpProgress: 0, xpTotal: 0 };
        
        if (fs.existsSync(playerDataPath)) {
            const buffer = fs.readFileSync(playerDataPath);
            const { parsed } = await nbt.parse(buffer);
            const simplified = nbt.simplify(parsed);
            inventory = simplified.Inventory || [];
            enderChest = simplified.EnderItems || [];
            
            // Extraer datos vitales
            vitals = {
                health: simplified.Health !== undefined ? simplified.Health : 20,
                foodLevel: simplified.foodLevel !== undefined ? simplified.foodLevel : 20,
                foodSaturation: simplified.foodSaturationLevel !== undefined ? simplified.foodSaturationLevel : 0,
                xpLevel: simplified.XpLevel || 0,
                xpProgress: simplified.XpP || 0,
                xpTotal: simplified.XpTotal || 0
            };
        }

        // 3. Leer Estadísticas (JSON)
        const statsPath = path.join(serverPath, levelName, 'stats', `${uuid}.json`);
        let stats = {};
        if (fs.existsSync(statsPath)) {
            stats = JSON.parse(fs.readFileSync(statsPath, 'utf8')).stats || {};
        }

        // 4. Leer Listas de Acceso (Ops, Whitelist, Bans)
        const readJsonList = (filename) => {
            try {
                const fPath = path.join(serverPath, filename);
                if (fs.existsSync(fPath)) return JSON.parse(fs.readFileSync(fPath, 'utf8'));
            } catch (e) {}
            return [];
        };

        const ops = readJsonList('ops.json');
        const whitelist = readJsonList('whitelist.json');
        const bannedPlayers = readJsonList('banned-players.json');

        const isOp = ops.some(o => o.uuid === uuid || o.name.toLowerCase() === playerName.toLowerCase());
        const isWhitelisted = whitelist.some(w => w.uuid === uuid || w.name.toLowerCase() === playerName.toLowerCase());
        const isBanned = bannedPlayers.some(b => b.uuid === uuid || b.name.toLowerCase() === playerName.toLowerCase());

        res.json({ inventory, enderChest, stats, vitals, isOp, isWhitelisted, isBanned });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// --- NUEVO: Endpoints para Whitelist ---

// Enviar comando al servidor (para whitelist y otros)
app.post('/execute-command/:id', async (req, res) => {
    const { command } = req.body;
    try {
        const container = docker.getContainer(req.params.id);
        // Adjuntar al stdin del contenedor para escribir el comando
        const stream = await container.attach({ stream: true, stdin: true, hijack: true });
        stream.write(command + "\n");
        stream.end();
        logActivity(`Comando enviado a ${req.params.id.substring(0, 12)}: ${command}`);
        res.json({ message: 'Comando enviado' });
    } catch (error) {
        logActivity(`Error enviando comando: ${error.message}`);
        res.status(500).json({ error: 'El servidor debe estar encendido para ejecutar comandos.' });
    }
});

// Leer whitelist.json
app.get('/whitelist/:serverName', (req, res) => {
    const serverPath = path.join(__dirname, 'servers', req.params.serverName);
    const whitelistPath = path.join(serverPath, 'whitelist.json');
    
    if (fs.existsSync(whitelistPath)) {
        try {
            const data = fs.readFileSync(whitelistPath, 'utf8');
            res.json(JSON.parse(data));
        } catch (e) { res.json([]); }
    } else { res.json([]); }
});

// Obtener icono del servidor
app.get('/server-icon/:serverName', (req, res) => {
    const serverPath = path.join(__dirname, 'servers', req.params.serverName);
    const iconPath = path.join(serverPath, 'server-icon.png');
    if (fs.existsSync(iconPath)) {
        res.sendFile(iconPath);
    } else {
        res.status(404).send('No icon');
    }
});

/**
 * Crear Backup Local (en el servidor)
 */
app.post('/local-backup/:id', async (req, res) => {
    try {
        const container = docker.getContainer(req.params.id);
        const info = await container.inspect();
        const mount = info.Mounts.find(m => m.Destination === '/data');
        
        if (!mount || !mount.Source) return res.status(500).json({ error: 'No se pudo localizar la carpeta del servidor.' });
        
        const serverPath = mount.Source;
        const backupsDir = path.join(serverPath, 'backups');
        
        if (!fs.existsSync(backupsDir)) {
            fs.mkdirSync(backupsDir, { recursive: true });
        }

        const timestamp = new Date().toISOString().replace(/T/, '_').replace(/\..+/, '').replace(/:/g, '-');
        const fileName = `backup_${timestamp}.zip`;
        const filePath = path.join(backupsDir, fileName);
        
        logActivity(`Iniciando backup local para ${info.Name}: ${fileName}`);

        // 1. Intentar guardar y desactivar autoguardado si está online
        const isRunning = info.State.Running;
        if (isRunning) {
            try {
                const stream = await container.attach({ stream: true, stdin: true, hijack: true });
                stream.write("save-all\n");
                stream.write("save-off\n");
                stream.end();
                await new Promise(resolve => setTimeout(resolve, 2000)); // Esperar flush
            } catch (e) {}
        }

        // 2. Crear ZIP
        const output = fs.createWriteStream(filePath);
        const archive = archiver('zip', { zlib: { level: 9 } });

        output.on('close', async () => {
            logActivity(`Backup completado: ${fileName} (${archive.pointer()} bytes)`);
            
            // 3. Reactivar guardado
            if (isRunning) {
                try {
                    const stream = await container.attach({ stream: true, stdin: true, hijack: true });
                    stream.write("save-on\n");
                    stream.end();
                } catch (e) {}
            }
            
            res.json({ message: 'Backup creado exitosamente en la carpeta /backups' });
        });

        archive.on('error', (err) => {
            logActivity(`Error en backup: ${err.message}`);
            res.status(500).json({ error: err.message });
        });

        archive.pipe(output);

        // Agregar archivos excluyendo la carpeta de backups para evitar bucles
        archive.glob('**/*', {
            cwd: serverPath,
            ignore: ['backups/**', 'backups']
        });

        archive.finalize();

    } catch (error) {
        logActivity(`Error general en backup: ${error.message}`);
        res.status(500).json({ error: error.message });
    }
});

// Descargar Backup (.zip)
app.get('/backup/:serverName', (req, res) => {
    const serverPath = path.join(__dirname, 'servers', req.params.serverName);
    
    if (!fs.existsSync(serverPath)) return res.status(404).send('Servidor no encontrado');

    const archive = archiver('zip', { zlib: { level: 9 } }); // Nivel máximo de compresión

    res.attachment(`${req.params.serverName}-backup.zip`);

    archive.on('error', (err) => res.status(500).send({ error: err.message }));
    archive.pipe(res);

    archive.directory(serverPath, false);
    archive.finalize();
});

// WebSockets para la consola
io.on('connection', (socket) => {
    let currentStream = null;
    let currentStatsStream = null;

    socket.on('attach-console', async (containerId) => {
        try {
            // Limpiar stream anterior si existe para no mezclar logs
            if (currentStream) currentStream.destroy();
            socket.removeAllListeners('send-command');

            const container = docker.getContainer(containerId);
            const stream = await container.attach({
                stream: true, stdout: true, stderr: true, logs: true, tail: 200
            });
            currentStream = stream;

            stream.on('data', (chunk) => {
                socket.emit('console-output', chunk.toString('utf8'));
            });

            socket.on('send-command', (command) => {
                container.attach({ stream: true, stdin: true, hijack: true }, (err, stream) => {
                    if(!err) stream.write(command + "\n");
                });
            });

        } catch (error) {
            socket.emit('error', 'Error conectando a consola: ' + error.message);
        }
    });

    // Streaming de Estadísticas (CPU/RAM)
    socket.on('attach-stats', async (containerId) => {
        try {
            // Limpiar stream anterior para evitar duplicados
            if (currentStatsStream) currentStatsStream.destroy();

            const container = docker.getContainer(containerId);
            container.stats({ stream: true }, (err, stream) => {
                if (err) return;
                currentStatsStream = stream;
                
                stream.on('data', (chunk) => {
                    try {
                        const stats = JSON.parse(chunk.toString());
                        
                        // Calcular porcentaje de CPU
                        if (!stats.cpu_stats || !stats.precpu_stats || !stats.cpu_stats.cpu_usage || !stats.precpu_stats.cpu_usage) return;
                        const cpuDelta = stats.cpu_stats.cpu_usage.total_usage - stats.precpu_stats.cpu_usage.total_usage;
                        const systemDelta = stats.cpu_stats.system_cpu_usage - stats.precpu_stats.system_cpu_usage;
                        const numCpus = stats.cpu_stats.online_cpus || 1;
                        
                        let cpuPercent = 0;
                        if (systemDelta > 0 && cpuDelta > 0) {
                            cpuPercent = (cpuDelta / systemDelta) * numCpus * 100.0;
                        }

                        socket.emit('stats-update', {
                            cpu: cpuPercent.toFixed(2),
                            memory: stats.memory_stats.usage,
                            memoryLimit: stats.memory_stats.limit
                        });
                    } catch (e) {}
                });
                socket.on('disconnect', () => stream.destroy());
            });
        } catch (error) {}
    });
});

// --- SISTEMA DE PLUGINS (Backend) ---
const PLUGINS_DIR = path.join(__dirname, 'plugins');

// Crear carpeta si no existe
if (!fs.existsSync(PLUGINS_DIR)) {
    fs.mkdirSync(PLUGINS_DIR);
}

// Cargar plugins desde subcarpetas (ej: plugins/mi-plugin/index.js)
fs.readdirSync(PLUGINS_DIR, { withFileTypes: true }).forEach(dirent => {
    if (dirent.isDirectory()) {
        const pluginDir = path.join(PLUGINS_DIR, dirent.name);
        const mainFile = path.join(pluginDir, 'index.js');
        
        if (fs.existsSync(mainFile)) {
            try {
                delete require.cache[require.resolve(mainFile)];
                const pluginLoader = require(mainFile);
                if (typeof pluginLoader === 'function') {
                    pluginLoader({ app, io, docker, logActivity, fs, path });
                    logActivity(`[SISTEMA] Plugin cargado: ${dirent.name}`);
                }
            } catch (e) {
                logActivity(`[ERROR] Falló al cargar plugin ${dirent.name}: ${e.message}`);
            }
        }
    }
});

// --- API PLUGINS BACKEND (Configuración desde Web) ---

// Listar plugins instalados y si tienen config
app.get('/list-backend-plugins', (req, res) => {
    try {
        const plugins = [];
        const items = fs.readdirSync(PLUGINS_DIR, { withFileTypes: true });
        
        items.forEach(dirent => {
            if (dirent.isDirectory()) {
                const hasIndex = fs.existsSync(path.join(PLUGINS_DIR, dirent.name, 'index.js'));
                const hasConfig = fs.existsSync(path.join(PLUGINS_DIR, dirent.name, 'config.json'));
                if (hasIndex) {
                    plugins.push({ name: dirent.name, hasConfig: hasConfig });
                }
            }
        });
        res.json(plugins);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// Leer configuración de plugin
app.get('/plugin-config/:name', (req, res) => {
    const pluginName = req.params.name;
    if (pluginName.includes('..') || pluginName.includes('/') || pluginName.includes('\\')) return res.status(403).json({ error: 'Inválido' });

    const configPath = path.join(PLUGINS_DIR, pluginName, 'config.json');
    if (!fs.existsSync(configPath)) return res.status(404).json({ error: 'No tiene config.json' });

    try { res.json({ content: fs.readFileSync(configPath, 'utf8') }); } 
    catch (e) { res.status(500).json({ error: 'Error leyendo configuración' }); }
});

// Guardar configuración de plugin
app.post('/plugin-config/:name', (req, res) => {
    const pluginName = req.params.name;
    const { content } = req.body;
    if (pluginName.includes('..') || pluginName.includes('/') || pluginName.includes('\\')) return res.status(403).json({ error: 'Inválido' });

    const configPath = path.join(PLUGINS_DIR, pluginName, 'config.json');
    try {
        JSON.parse(content); // Validar JSON
        fs.writeFileSync(configPath, content, 'utf8');
        res.json({ message: 'Configuración guardada. Reinicia el panel para aplicar cambios.' });
    } catch (e) { res.status(400).json({ error: 'JSON inválido: ' + e.message }); }
});

// --- SISTEMA DE PLUGINS WEB (Frontend) ---
const WEB_PLUGINS_DIR = path.join(__dirname, 'web-plugins');

// Crear carpeta si no existe
if (!fs.existsSync(WEB_PLUGINS_DIR)) {
    fs.mkdirSync(WEB_PLUGINS_DIR);
}

// Servir archivos estáticos de plugins
app.use('/web-plugins', express.static(WEB_PLUGINS_DIR));

// Endpoint para listar plugins de frontend
app.get('/list-web-plugins', (req, res) => {
    try {
        const plugins = [];
        const items = fs.readdirSync(WEB_PLUGINS_DIR, { withFileTypes: true });
        
        items.forEach(item => {
            if (item.isDirectory()) {
                const pluginPath = path.join(WEB_PLUGINS_DIR, item.name);
                const files = fs.readdirSync(pluginPath);
                // Buscar archivos .js dentro de la carpeta del plugin
                files.forEach(file => {
                    if (file.endsWith('.js')) {
                        plugins.push(`/web-plugins/${item.name}/${file}`);
                    }
                });
            }
        });
        res.json(plugins);
    } catch (e) {
        res.json([]);
    }
});

server.listen(PORT, '0.0.0.0', () => {
    const interfaces = os.networkInterfaces();
    let lanIp = 'localhost';
    
    // Buscar IP válida ignorando interfaces de Docker
    for (const name of Object.keys(interfaces)) {
        // Ignorar interfaces virtuales comunes de Docker/VMs
        if (name.includes('docker') || name.includes('br-') || name.includes('veth') || name.includes('virbr')) continue;
        
        for (const iface of interfaces[name]) {
            if (iface.family === 'IPv4' && !iface.internal) {
                // Priorizar IPs típicas de red local (192.168.x.x)
                if (iface.address.startsWith('192.168.')) { lanIp = iface.address; break; }
                if (lanIp === 'localhost') lanIp = iface.address;
            }
        }
        if (lanIp.startsWith('192.168.')) break; // Ya encontramos la mejor opción
    }
    const protocol = isHttps ? 'https' : 'http';
    logActivity(`Panel iniciado. Accede desde otra PC en: ${protocol}://${lanIp}:${PORT}`);
    if (!isHttps) console.log('NOTA: Ejecutando en modo HTTP.');
});