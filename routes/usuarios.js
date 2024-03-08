require('dotenv').config();
const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const jwt = require('jwt-simple');

const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./db/empleadosDB.sqlite');
const dbPath = './db/empleadosDB.sqlite';


const { checkToken } = require('../middleware');


// ===================Api verifica token - Seguridad=========================
router.post('/apiVerificaToken', checkToken, function(req, res, next) {
  
  //console.log(req.userId);
  //console.log(req.rolId);
  if(req.userId != undefined)
  {
    res.json({
      successful:'Token Validado',
      numero:'001'
    });
  }
  
});

// Ruta principal para mostrar la lista de usuarios y el formulario de ingreso
router.get('/', (req, res) => {
  const db = new sqlite3.Database(dbPath);
  db.all("SELECT * FROM usuarios", [], (err, rows) => {
    if (err) {
      throw err;
    }
    // Pasar 'usuario' y un objeto 'usuarioSeleccionado' vacío si no estamos editando
    res.render('usuarios', { usuarios: rows, usuarioSeleccionado: {} });
  });
  db.close();
});
// CRUD de usuarios

// Crear usuario
router.post('/usuario', async (req, res) => {
  console.log(req.body);

  const { nombre, rol, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  db.run(`INSERT INTO usuarios (nombre, rol, password) VALUES (?, ?, ?)`, [nombre, rol, hashedPassword], function(err) {
    if (err) {
      res.status(500).json({ error: err.message });
    } else {
      res.status(201).json({ id: this.lastID });
    }
  });
});

// Leer usuario (por ID)
router.get('/usuario/:id', (req, res) => {
  const id = req.params.id;

  db.get(`SELECT id, nombre, rol FROM usuarios WHERE id = ?`, [id], (err, row) => {
    if (err) {
      res.status(500).json({ error: err.message });
    } else if (row) {
      res.json(row);
    } else {
      res.status(404).json({ error: 'Usuario no encontrado' });
    }
  });
});

// Actualizar usuario
router.put('/usuario/:id', async (req, res) => {
  const { nombre, rol, password } = req.body;
  const hashedPassword = password ? await bcrypt.hash(password, 10) : undefined;
  const id = req.params.id;

  db.run(`UPDATE usuarios SET nombre = ?, rol = ?${password ? ', password = ?' : ''} WHERE id = ?`, 
    password ? [nombre, rol, hashedPassword, id] : [nombre, rol, id], function(err) {
    if (err) {
      res.status(500).json({ error: err.message });
    } else if (this.changes === 0) {
      res.status(404).json({ error: 'Usuario no encontrado' });
    } else {
      res.json({ message: 'Usuario actualizado' });
    }
  });
});

// Eliminar usuario
router.delete('/usuario/:id', (req, res) => {
  const id = req.params.id;

  db.run(`DELETE FROM usuarios WHERE id = ?`, [id], function(err) {
    if (err) {
      res.status(500).json({ error: err.message });
    } else if (this.changes === 0) {
      res.status(404).json({ error: 'Usuario no encontrado' });
    } else {
      res.json({ message: 'Usuario eliminado' });
    }
  });
});


module.exports = router;
