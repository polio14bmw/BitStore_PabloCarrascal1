// Variable Mongoose
let mongoose = require("mongoose");
// metodo que permite crear esquemas desde node/express
let Schema = mongoose.Schema;

// Se crea el esquema
let estudianteSchema = Schema({
  nombres: String,
  codigo: String,
  correo: String,
  puntos: Number,
  fechaRegistro: { type: Date, default: Date.now },
});
// Se exporta el modulo
module.exports = mongoose.model("estudiante", estudianteSchema);