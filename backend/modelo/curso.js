// Variable Mongoose
let mongoose = require("mongoose");
const { listenerCount } = require("./detalleCompra");
// metodo que permite crear esquemas desde node/express
let Schema = mongoose.Schema;

// Se crea el esquema
let cursoSchema = Schema({
  nombre: String,
  descripcion: String,
  imagen: String,
  precioTotal: Number,
  precioCompra: Number,
  cupos: Number,
  idcategoria: { type: Schema.ObjectId, ref: "categoria" },
  puntos: Number,
});
// Se exporta el modulo
module.exports = mongoose.model("curso", cursoSchema);