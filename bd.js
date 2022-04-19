const mysql = require('mysql');

const pool = mysql.createPool({
host: 'localhost',
user: 'root',
password: 'C0n3ct1v1d4d_pnt_2018',
// password: '',
database: 'declarantes_db'
})

const mysqlConnection = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'C0n3ct1v1d4d_pnt_2018',
    // password: '',
    database: 'declarantes_db'
});

mysqlConnection.connect(function(err){
    if(err){
        console.log(err);
        console.log('SIN CONEXIÓN');
        return;
    }else{
        console.log('Conectado...');
    }
});
module.exports=mysqlConnection;
//module.exports=pool;
