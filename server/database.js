const sqlite3 = require('sqlite3').verbose();
const path = require('path');

// Crear la conexión a la base de datos
const db = new sqlite3.Database(path.join(__dirname, 'database.sqlite'));

// Inicializar la base de datos
function initDatabase() {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `, (err) => {
    if (err) {
      console.error('Error creating database:', err);
    } else {
      console.log('Database initialized successfully');
    }
  });
}

module.exports = { db, initDatabase };