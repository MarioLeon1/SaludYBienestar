const express = require('express');
const promBundle = require('express-prom-bundle');
const prometheus = require('prom-client');

// Crear contadores personalizados
const loginCounter = new prometheus.Counter({
    name: 'syb_login_total',
    help: 'Total number of successful logins'
});

const registerCounter = new prometheus.Counter({
    name: 'syb_register_total',
    help: 'Total number of successful registrations'
});

const pageViewCounter = new prometheus.Counter({
    name: 'syb_page_views_total',
    help: 'Total number of page views'
});

// Configurar el middleware de Prometheus
const metricsMiddleware = promBundle({
    includeMethod: true,
    includePath: true,
    includeStatusCode: true,
    includeUp: true,
    customLabels: {app: 'syb-api'},
    promClient: {
        collectDefaultMetrics: {
            timeout: 1000
        }
    }
});

const cors = require('cors');
const bcryptjs = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { db, initDatabase } = require('./database');

const app = express();
const port = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(metricsMiddleware);

// Middleware para logs y conteo de vistas de página
app.use((req, res, next) => {
    console.log(`${new Date().toISOString()} ${req.method} ${req.url}`);
    console.log('Body:', req.body);
    // Incrementar contador de vistas solo para peticiones GET a la raíz
    if (req.method === 'GET' && req.url === '/') {
        pageViewCounter.inc();
    }
    next();
});

// Registro de usuarios con más logs y métricas
app.post('/register', async (req, res) => {
    console.log('Recibida petición de registro:', req.body);
    const { name, email, password } = req.body;

    try {
        console.log('Verificando email existente');
        db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
            if (err) {
                console.error('Error en la consulta:', err);
                return res.status(500).json({ message: 'Error en el servidor' });
            }
            if (user) {
                console.log('Email ya registrado');
                return res.status(400).json({ message: 'El email ya está registrado' });
            }

            console.log('Hasheando contraseña');
            const hashedPassword = await bcryptjs.hash(password, 10);

            console.log('Insertando nuevo usuario');
            db.run('INSERT INTO users (name, email, password) VALUES (?, ?, ?)',
                [name, email, hashedPassword],
                (err) => {
                    if (err) {
                        console.error('Error al insertar:', err);
                        return res.status(500).json({ message: 'Error al registrar usuario' });
                    }
                    console.log('Usuario registrado exitosamente');
                    // Incrementar contador de registros exitosos
                    registerCounter.inc();
                    res.status(201).json({ message: 'Usuario registrado exitosamente' });
                }
            );
        });
    } catch (error) {
        console.error('Error en el registro:', error);
        res.status(500).json({ message: 'Error en el servidor' });
    }
});

// Login de usuarios con más logs y métricas
app.post('/login', (req, res) => {
    console.log('Recibida petición de login:', req.body);
    const { email, password } = req.body;

    db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
        if (err) {
            console.error('Error en la consulta:', err);
            return res.status(500).json({ message: 'Error en el servidor' });
        }
        if (!user) {
            console.log('Usuario no encontrado');
            return res.status(401).json({ message: 'Credenciales inválidas' });
        }

        try {
            console.log('Verificando contraseña');
            const validPassword = await bcryptjs.compare(password, user.password);
            if (!validPassword) {
                console.log('Contraseña incorrecta');
                return res.status(401).json({ message: 'Credenciales inválidas' });
            }

            console.log('Generando token');
            const token = jwt.sign(
                { userId: user.id, email: user.email },
                process.env.JWT_SECRET || 'tu_secreto_jwt',
                { expiresIn: '24h' }
            );

            console.log('Login exitoso');
            // Incrementar contador de logins exitosos
            loginCounter.inc();
            res.json({
                token,
                user: {
                    id: user.id,
                    name: user.name,
                    email: user.email
                }
            });
        } catch (error) {
            console.error('Error en la verificación:', error);
            res.status(500).json({ message: 'Error en el servidor' });
        }
    });
});

initDatabase();
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});