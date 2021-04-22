/* Variable express */
let express = require("express")
/* Importamos el controlador de usuario */
let Usuario = require("../controllers/usuario.js")

/* Creamos la api */
let api = express.Router();

/* Servicio POST (registrar) http://localhost:3001/api/registrarUsuario */
api.post("/registrarUsuario", Usuario.registrarUsuario)
/* Servicio para el login */
api.post("/login", Usuario.login);

/* Exportamos el modulo */
module.exports = api;