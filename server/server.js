const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const promBundle = require('express-prom-bundle');
const { db, initDatabase } = require('./database');

const app = express();
const port = process.env.PORT || 3000;

const metricsMiddleware = promBundle({
  includeMethod: true,
  includePath: true,
  includeStatusCode: true,
  includeUp: true,
  customLabels: {app: 'syb-api'},
  promClient: {
    collectDefaultMetrics: {
      timeout: 5000
    }
  }
});

app.use(metricsMiddleware);
app.use(cors());
app.use(express.json());
app.use(express.static('../'));

// Inicializar la base de datos
initDatabase();

// Registro de usuarios
app.post('/api/register', async (req, res) => {
  const { name, email, password } = req.body;

  try {
    // Verificar si el email ya existe
    db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
      if (err) {
        return res.status(500).json({ message: 'Error en el servidor' });
      }
      if (user) {
        return res.status(400).json({ message: 'El email ya está registrado' });
      }

      // Hash de la contraseña
      const hashedPassword = await bcrypt.hash(password, 10);

      // Insertar nuevo usuario
      db.run('INSERT INTO users (name, email, password) VALUES (?, ?, ?)',
        [name, email, hashedPassword],
        (err) => {
          if (err) {
            return res.status(500).json({ message: 'Error al registrar usuario' });
          }
          res.status(201).json({ message: 'Usuario registrado exitosamente' });
        }
      );
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error en el servidor' });
  }
});

// Login de usuarios
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;

  db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
    if (err) {
      return res.status(500).json({ message: 'Error en el servidor' });
    }
    if (!user) {
      return res.status(401).json({ message: 'Credenciales inválidas' });
    }

    try {
      const validPassword = await bcrypt.compare(password, user.password);
      if (!validPassword) {
        return res.status(401).json({ message: 'Credenciales inválidas' });
      }

      const token = jwt.sign(
        { userId: user.id, email: user.email },
        process.env.JWT_SECRET || 'tu_secreto_jwt',
        { expiresIn: '24h' }
      );

      res.json({
        token,
        user: {
          id: user.id,
          name: user.name,
          email: user.email
        }
      });
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: 'Error en el servidor' });
    }
  });
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});