/**
 * Plugin de Ejemplo: Mensaje de Bienvenida con Configuración
 */
module.exports = ({ logActivity, fs, path }) => {
    // Ruta al archivo config.json DENTRO de la carpeta de este plugin
    const CONFIG_PATH = path.join(__dirname, 'config.json');

    // 1. Definir la configuración por defecto
    const defaultConfig = {
        activado: true,
        mensaje: "¡Hola! El panel se ha iniciado correctamente.",
        repetirVeces: 1
    };

    let config = { ...defaultConfig };

    // 2. Intentar cargar la configuración si el archivo ya existe
    if (fs.existsSync(CONFIG_PATH)) {
        try {
            const rawData = fs.readFileSync(CONFIG_PATH, 'utf8');
            const userConfig = JSON.parse(rawData);
            // Mezclar con defaults por si faltan opciones nuevas
            config = { ...defaultConfig, ...userConfig };
            logActivity('[MensajeBienvenida] Configuración cargada desde config.json');
        } catch (e) {
            logActivity(`[MensajeBienvenida] Error leyendo config: ${e.message}`);
        }
    } else {
        // 3. Si no existe, CREAR el archivo config.json
        try {
            fs.writeFileSync(CONFIG_PATH, JSON.stringify(defaultConfig, null, 2));
            logActivity('[MensajeBienvenida] Archivo config.json creado por primera vez.');
        } catch (e) {
            logActivity(`[MensajeBienvenida] Error creando config: ${e.message}`);
        }
    }

    // 4. Ejecutar lógica usando la configuración
    if (config.activado) {
        for (let i = 0; i < config.repetirVeces; i++) {
            logActivity(`[MensajeBienvenida] ${config.mensaje}`);
        }
    }
};