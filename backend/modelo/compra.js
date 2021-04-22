// Variable Mongoose
let mongoose = require("mongoose");
// metodo que permite crear esquemas desde node/express
let Schema = mongoose.Schema;

// Se crea el esquema
let compraSchema = Schema({
  idEstudiante: { type: Schema.ObjectId, ref: "estudiante" },
  idUsuario: { type: Schema.ObjectId, ref: "usuario" },
  fechaCompra: { type: Date, default: Date.now },
});
// Se exporta el modulo
module.exports = mongoose.model("compra", compraSchema);
