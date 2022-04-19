console.log('Servidor para consulta de declaraciones de situación patrimonial e interés de los servidores públicos del IMAIP')

const express = require('express')
const bodyParser = require('body-parser')
const app = express()

//---------------------- Ajustes (app.set) ----------------------------------
app.set('puerto', process.env.PORT || 3000)

//-------------------- Middlewares (app.use) --------------------------------
app.use(express.urlencoded()) //mi servidor va a trabajar con
// url encoded a través de la lógica de intercambio "Express JS"
app.use(bodyParser.json())
//app.use(bodyParser.urlencoded({ extended: true }))
app.use(express.json())

//Rutas
app.use(require('./consultas'))

app.use((err, req, res, next) => {
    // Middleware que verifica que el objecto en el body sea un JSON válido
    if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
        console.error(err);
        return res.sendStatus(400); // Bad request
    }

    next();
});

//Respuesta del servidor
app.get('/', function(req, res){
    res.send('Servidor para declaraimaip corriendo...')
});

app.listen(app.get('puerto'), function(){
    console.log('Servidor encendido en el puerto : ',app.get('puerto'))
});