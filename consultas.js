const express = require('express');
const router = express.Router();

const jwt = require('jsonwebtoken');
const config = require('./config');

const mysqlConnection = require('./bd');
const pool = require('./bd');

const CryptoJS = require('crypto-js');


//POST para token

router.post('/token', (req, res) => {

    var [id, secret]=[]
    var [user, pass]=[]

    if(req.headers.authorization && req.body.username && req.body.password){
        const b64auth = (req.headers.authorization || '').split(' ')[1] || ''
        var [id, secret] = Buffer.from(b64auth, 'base64').toString().split(':') //Autorización a través de Header
        var [user, pass] = ([req.body.username,req.body.password])
    }else if(req.body.username && req.body.password && req.body.client_id && req.body.client_secret){
        var [id, secret] = ([req.body.client_id,req.body.client_secret]) //Autorización a través del Body
        var [user, pass] = ([req.body.username,req.body.password])
    }else{
        return res.status(401).send({
        code: 'No Authorized',
        message: 'Error en la autorización de credenciales'
        });
    }

    mysqlConnection.query('SELECT tokenAutorizacion, username from credenciales',(err,rows,fields)=>{
    //Se consultan los token de autorizacion existentes    
        if(!err){
            var Autorizacion=false
            for(x in rows){//Si existe coincidencia entra a la autorizacion

                var decryptedDataAuth  = JSON.parse(CryptoJS.AES.decrypt(rows[x].tokenAutorizacion, config.key).toString(CryptoJS.enc.Utf8));
                var decryptedDataUser  = JSON.parse(CryptoJS.TripleDES.decrypt(rows[x].username, config.key).toString(CryptoJS.enc.Utf8));

                if(JSON.stringify(decryptedDataAuth) === JSON.stringify([id,secret]) && JSON.stringify(decryptedDataUser) === JSON.stringify([user,pass])){
                    Autorizacion=true
                    break
                }
            }
            if(Autorizacion){
               //El jasonwebtoken recibe un dato que es la manera de autenticación (dato cifrado que se envía entre el cliente y el servidor)
               //Tambien recibe un "secret" el cual es un algoritmo que cifra el token a través de una llave
               //Por último un parámetro de tiempo de expiración
                        jwt.sign({tokenAuth: CryptoJS.AES.encrypt(JSON.stringify(user), config.key).toString()}, config.secret, {expiresIn: 3600},(err,accessToken)=>{
                                res.status(200).send({
                                    access_token: accessToken,
                                    token_type: "Bearer",
                                    expires_in: 3600
                                });
                    });
                }else{

                    return res.status(401).send({
                        code: 'No Authorized',
                        message: 'Error en la autorización de credenciales'
                    });
                }
                }else{
                    return res.status(401).send({
                        code: 'No Authorized',
                        message: 'Error en la autorización de credenciales'
                    });
                }
            });
    
    }); //Fin POST para token

router.post('/signup', verificarToken, (req, res) => {
    jwt.verify(req.token,config.secret,(err,authData)=>{
        if(err){
            res.status(401).json({
                code: 'No Authorized',
                message: 'No se cuenta con autorización',
            });
        }else{
            if(req.body.nuevoAuth){
            if(req.body.nuevoAuth.username && req.body.nuevoAuth.password && req.body.nuevoAuth.client_id && req.body.nuevoAuth.client_secret && req.body.credencial){ //Se verifica formato de body
            const [user,pass] = [req.body.nuevoAuth.client_id,req.body.nuevoAuth.client_secret]
            const [usuario,contraseña] = [req.body.nuevoAuth.username,req.body.nuevoAuth.password]
            const credencial = req.body.credencial

            if(credencial===''+config.administrador){ //Se verifica que la llave de administrador sea correcta
            //encriptacion con AES
            var cipher_id_secret = CryptoJS.AES.encrypt(JSON.stringify([user,pass]), config.key).toString();
            
            //encriptacion con Triple DES
            var cipher_user_pass = CryptoJS.TripleDES.encrypt(JSON.stringify([usuario,contraseña]), config.key).toString();
            
            mysqlConnection.query("INSERT INTO credenciales (tokenAutorizacion,username) values ('"+cipher_id_secret+"','"+cipher_user_pass+"')",(err,rows,fields)=>{
                if(err){
                    return res.status(400).send({
                        code: 'Authorized',
                        message: 'ERROR EN CONSULTA !!!'
                    });
                }else{
                    return res.status(200).send({
                        code: 'Authorized',
                        message: 'Nuevas credenciales de autorizacion ingresadas'
                    });
                }
            });}else{
                res.status(401).json({
                    code: 'Authorized',
                    message: 'No cuenta con autorizacion de administrador',
                });
        }
    }else{
                res.status(400).json({
                    code: 'Authorized',
                    message: 'Error',
                });
            }
        }else{
            res.status(400).json({
                code: 'Authorized',
                message: 'Error',
            });
        }
        }
    });
        
});

// router.post('/prueba', (req, res) => {

//     console.log(req.body)
//     if(req.params.prueba=='hola')
//     res.send('dasdasfasdfdf');
//     else
//     res.send('dasda 1212312312312323 ')
// });

//POST para consultas

router.post('/:info', verificarToken, (req, res) => {
    
    var urlDeclaracion=null

    if( req.params.info=='inicial' || req.params.info=='modificacion' || req.params.info=='conclusion' ){
        switch (req.params.info) {
            case 'inicial':
                urlDeclaracion='I'    
                break;
            case 'modificacion':
                urlDeclaracion='M'
                break;
            case 'conclusion':
                urlDeclaracion='C'
                break;
            default:
                return res.sendStatus(404); //Wrong page
        }
    }else{
        return res.sendStatus(404); //Wrong page
    }
            //Verifica autorización
            //Desencripta el token a través del "secret" que es mi llave secreta de autorización
    jwt.verify(req.token,config.secret,(err,authData)=>{

        if(err){
            res.status(401).json({code: 'No Authorized', message: 'No se cuenta con autorización'});
        }
        else{
       
            var page;
            var limit;
            const I='I';
            const M='M';
            const C='C'; //Esta variable no se usa
        
            page = (req.body.page)?(req.body.page<1)?1:req.body.page:1; //página
             
            limit = (req.body.pageSize)?(req.body.pageSize)>200?200:(req.body.pageSize)<1?1:(req.body.pageSize):(req.body.pageSize==0)?1:10;
            //número máximo de entradas/elementos/registros por página
            //Si es menor a 1 será 1
            //Si no está definido el valor será 10
            //Si es mayor a 200 será 200
        
            var nextPage=true, prevPage=true; //parámetros para hasPreviousPage y hasNextPage

            //Se agrupan los elementos en base a la página de consulta y el limite de elementos por página
            const indexInicio=(page-1)*limit;
            const indexFin=page*limit;
        
            var consultaQuery=[];
            var busquedaQuery=[];
            var consultaSort=[];
            var parametroSort=[];
            var miOrdenamiento=[];
            var miConsulta=[];

            const parametrosPrimerNivel=['id','nombres','primerApellido','segundoApellido','escolaridadNivel']
            const parametrosPrimerNivel_db=['datosgenerales.ID_declarante','datosgenerales.nombre','datosgenerales.primerApellido','datosgenerales.segundoApellido','datoscurricularesdeclarante_n.escolaridadValor']

            const parametrosSegundoNivel=['nombreEntePublico','entidadFederativa','municipioAlcaldia','empleoCargoComision','nivelOrdenGobierno','nivelEmpleoCargoComision']
            const parametrosSegundoNivel_db=['datosempleocargocomision.nombreEntePublico','datosempleocargocomision.entidadFederativaValorDatosEmpleo','datosempleocargocomision.municipioAlcaldiaValorDatosEmpleo','datosempleocargocomision.empleoCargoComision','datosempleocargocomision.nivelOrdenGobierno','datosempleocargocomision.nivelEmpleoCargoComision']

            const parametrosTercerNivel=['superficieConstruccion','superficieTerreno','valorAdquisicion']
            const parametrosTercerNivel_db=['bienesinmuebles_n.superficieConstruccionValor','bienesinmuebles_n.superficieTerrenoValor','bienesinmuebles_n.valorAdquisicionValor']

            const parametrosExtras=['formaAdquisicion','totalIngresosNetos']
            const parametrosExtras_db=['bienesinmuebles_n.formaAdquisicionValor','ingresos.ingresoNetoDeclaranteValor']

            if(req.body.query && !(Object.entries(req.body.query).length===0)){ //Verifica que se cuente con una consulta

                for(i in parametrosPrimerNivel){
                    (req.body.query[parametrosPrimerNivel[i]])?(busquedaQuery.push(parametrosPrimerNivel_db[i]),consultaQuery.push(req.body.query[parametrosPrimerNivel[i]])):{};
                }
                for(i in parametrosSegundoNivel){
                    (req.body.query.datosEmpleoCargoComision)?(req.body.query.datosEmpleoCargoComision[parametrosSegundoNivel[i]])?(busquedaQuery.push(parametrosSegundoNivel_db[i]),consultaQuery.push(req.body.query.datosEmpleoCargoComision[parametrosSegundoNivel[i]])):{}:{};
                }
                for(i in parametrosTercerNivel){
                    (req.body.query.bienesInmuebles)?(req.body.query.bienesInmuebles[parametrosTercerNivel[i]])?(req.body.query.bienesInmuebles[parametrosTercerNivel[i]].max)?(busquedaQuery.push(parametrosTercerNivel_db[i]+".max"),consultaQuery.push(''+req.body.query.bienesInmuebles[parametrosTercerNivel[i]].max)):{}:{}:{};
                    (req.body.query.bienesInmuebles)?(req.body.query.bienesInmuebles[parametrosTercerNivel[i]])?(req.body.query.bienesInmuebles[parametrosTercerNivel[i]].min)?(busquedaQuery.push(parametrosTercerNivel_db[i]+".min"),consultaQuery.push(''+req.body.query.bienesInmuebles[parametrosTercerNivel[i]].min)):{}:{}:{};
                }
                    (req.body.query.bienesInmuebles)?(req.body.query.bienesInmuebles[parametrosExtras[0]])?(busquedaQuery.push(parametrosExtras_db[0]),consultaQuery.push(''+req.body.query.bienesInmuebles[parametrosExtras[0]])):{}:{};
                    (req.body.query[parametrosExtras[1]])?(req.body.query[parametrosExtras[1]].min)?(busquedaQuery.push(parametrosExtras_db[1]+".min"),consultaQuery.push(''+req.body.query[parametrosExtras[1]].min)):{}:{};
                    (req.body.query[parametrosExtras[1]])?(req.body.query[parametrosExtras[1]].max)?(busquedaQuery.push(parametrosExtras_db[1]+".max"),consultaQuery.push(''+req.body.query[parametrosExtras[1]].max)):{}:{};

                    miConsulta = prepararQuery(busquedaQuery,consultaQuery); //Funcion para convertir los parametros de consulta en lenguaje SQL
                    miConsulta = "WHERE metadata.tipoDeclaracion LIKE '"+urlDeclaracion+"%'"+miConsulta
                    console.log("Mi consulta: "+miConsulta);

            }else{miConsulta = "WHERE metadata.tipoDeclaracion LIKE '"+urlDeclaracion+"%'"}
            
            if(req.body.sort && !(Object.entries(req.body.sort).length===0)){ //Verifica que se cuente con parametros de ordenamiento
                
            for(i in parametrosPrimerNivel){
                (req.body.sort[parametrosPrimerNivel[i]])?(consultaSort.push(parametrosPrimerNivel_db[i]),parametroSort.push(req.body.sort[parametrosPrimerNivel[i]])):{};
            }
            for(i in parametrosSegundoNivel){
                 (req.body.sort.datosEmpleoCargoComision)?(req.body.sort.datosEmpleoCargoComision[parametrosSegundoNivel[i]])?(consultaSort.push(parametrosSegundoNivel_db[i]),parametroSort.push(req.body.sort.datosEmpleoCargoComision[parametrosSegundoNivel[i]])):{}:{};
            }
            for(i in parametrosTercerNivel){
                 (req.body.sort.bienesInmuebles)?(req.body.sort.bienesInmuebles[parametrosTercerNivel[i]])?(consultaSort.push(parametrosTercerNivel_db[i]),parametroSort.push(''+req.body.sort.bienesInmuebles[parametrosTercerNivel[i]])):{}:{};
            }
            
            (req.body.sort.bienesInmuebles)?(req.body.sort.bienesInmuebles[parametrosExtras[0]])?(consultaSort.push(parametrosExtras_db[0]),parametroSort.push(''+req.body.sort.bienesInmuebles[parametrosExtras[0]])):{}:{};
            (req.body.sort[parametrosExtras[1]])?(consultaSort.push(parametrosExtras_db[1]),parametroSort.push(''+req.body.sort[parametrosExtras[1]])):{};
 
            miOrdenamiento = prepararSort(consultaSort,parametroSort); //Funcion para convertir los ordenamiento en lenguaje SQL
            //console.log("Mi ordenamiento: "+miOrdenamiento);
            
    }
                
    var miConsultaQuery=
    "select * , datosgenerales.ID_declarante as declarante_ID from datosgenerales inner join domiciliodeclarante on datosgenerales.ID_declarante=domiciliodeclarante.ID_declarante inner join datoscurricularesdeclarante on datosgenerales.ID_declarante=datoscurricularesdeclarante.ID_declarante inner join datosempleocargocomision on datosgenerales.ID_declarante=datosempleocargocomision.ID_declarante inner join experiencialaboral on datosgenerales.ID_declarante=experiencialaboral.ID_declarante inner join datospareja on datosgenerales.ID_declarante=datospareja.ID_declarante inner join datosdependienteeconomico on datosgenerales.ID_declarante=datosdependienteeconomico.ID_declarante inner join ingresos on datosgenerales.ID_declarante=ingresos.ID_declarante inner join bienesinmuebles on datosgenerales.ID_declarante=bienesinmuebles.ID_declarante inner join vehiculos on datosgenerales.ID_declarante=vehiculos.ID_declarante inner join bienesmuebles on datosgenerales.ID_declarante=bienesmuebles.ID_declarante inner join adeudospasivos on datosgenerales.ID_declarante=adeudospasivos.ID_declarante inner join prestamocomodato on datosgenerales.ID_declarante=prestamocomodato.ID_declarante inner join participacion on datosgenerales.ID_declarante=participacion.ID_declarante inner join participaciontomadecisiones on datosgenerales.ID_declarante=participaciontomadecisiones.ID_declarante inner join apoyos on datosgenerales.ID_declarante=apoyos.ID_declarante inner join representaciones on datosgenerales.ID_declarante=representaciones.ID_declarante inner join clientesprincipales on datosgenerales.ID_declarante=clientesprincipales.ID_declarante inner join beneficiosprivados on datosgenerales.ID_declarante=beneficiosprivados.ID_declarante inner join fideicomisos on datosgenerales.ID_declarante=fideicomisos.ID_declarante inner join metadata on datosgenerales.ID_declarante=metadata.ID_declarante left join actividadanualanterior on datosgenerales.ID_declarante=actividadanualanterior.ID_declarante left join datoscurricularesdeclarante_n on datosgenerales.ID_declarante=datoscurricularesdeclarante_n.ID_declarante left join bienesinmuebles_n on datosgenerales.ID_declarante=bienesinmuebles_n.ID_declarante "+miConsulta+" group by datosgenerales.ID_declarante "+miOrdenamiento+""
    //console.log(miConsultaQuery)
    pool.query(miConsultaQuery, async function(err,rows,fields) { //Se abre espacio de consultas a la base de datos (se cierra automaticamente al terminar la primera transaccion)
            
        if(!err){

//---------------------------- S U B C O N S U L T A S  Y  O R D E N A M I E N T O  D E  R E S U L T A D O S --------------------------------------------------------------------
                           
            try {
                 
                misDatosCurricularesN=[]

                for(let j in rows){
                    var queryMisDatosCurricularesN = await getResult("select * from datoscurricularesdeclarante_n where ID_declarante = '"+rows[j].declarante_ID+"' ")
                    misDatosCurricularesN[j]=(typeof queryMisDatosCurricularesN !== 'undefined' && queryMisDatosCurricularesN)?queryMisDatosCurricularesN:{}
                }

//INICIO Ordenamiento de datosCurriculares

                misEscolaridades=[]
                misEscolaridadesAux=[]
                        
                for(let x in misDatosCurricularesN){
                    for(let y in misDatosCurricularesN[x]){
                        misEscolaridades.push({   
                            tipoOperacion:misDatosCurricularesN[x][y].operacion,                                     
                            nivel:{
                                clave:misDatosCurricularesN[x][y].escolaridadClave,
                                valor:misDatosCurricularesN[x][y].escolaridadValor
                            },
                            institucionEducativa:{
                                nombre:misDatosCurricularesN[x][y].institucionEducativaNiombre,
                                ubicacion:misDatosCurricularesN[x][y].institucionEducativaUbicacion
                            },
                            carreraAreaConocimiento:misDatosCurricularesN[x][y].carreraAreaConocimiento,
                            estatus:misDatosCurricularesN[x][y].estatus,
                            documentoObtenido:misDatosCurricularesN[x][y].documentoObtenido,
                            fechaObtencion:formatFecha(misDatosCurricularesN[x][y].fechaObtencion)
                        })
                    }
                    misEscolaridadesAux[x]=misEscolaridades
                    misEscolaridades=[]
                }
                            
//FIN Ordenamiento de datosCurriculares
                                    
                misOtrosEmpleosN=[]

                for(let j in rows){
                    var queryMisOtrosEmpleosN = await getResult("select * from otroempleocargocomision_n where ID_declarante = '"+rows[j].declarante_ID+"' ")
                    misOtrosEmpleosN[j]=(typeof queryMisOtrosEmpleosN !== 'undefined' && queryMisOtrosEmpleosN)?queryMisOtrosEmpleosN:{}
                }

//INICIO Ordenamiento de otrosEmpleoCargoComision

                misOtrosEmpleos=[]
                misOtrosEmpleosAux=[]
                        
                for(let x in misOtrosEmpleosN){
                    for(let y in misOtrosEmpleosN[x]){
                        misOtrosEmpleos.push({
                            nivelOrdenGobierno:misOtrosEmpleosN[x][y].nivelOrdenGobierno,
                            ambitoPublico:misOtrosEmpleosN[x][y].ambitoPublico,
                            nombreEntePublico:misOtrosEmpleosN[x][y].nombreEntePublico,
                            areaAdscripcion:misOtrosEmpleosN[x][y].areaAdscripcion,
                            empleoCargoComision:misOtrosEmpleosN[x][y].empleoCargoComision,
                            contratadoPorHonorarios:(misOtrosEmpleosN[x][y].contratadoPorHonorarios)?true:false,
                            nivelEmpleoCargoComision:misOtrosEmpleosN[x][y].nivelEmpleoCargoComision,
                            funcionPrincipal:misOtrosEmpleosN[x][y].funcionPrincipal,
                            fechaTomaPosesion:formatFecha(misOtrosEmpleosN[x][y].fechaTomaPosesion),
                            telefonoOficina:{
                                telefono:misOtrosEmpleosN[x][y].telefonoOficina,
                                extension:misOtrosEmpleosN[x][y].extensionOficina
                            },
                            domicilioMexico:{
                                calle:misOtrosEmpleosN[x][y].calleOficina,
                                numeroExterior:misOtrosEmpleosN[x][y].numeroExteriorDatosEmpleo,
                                numeroInterior:misOtrosEmpleosN[x][y].numeroInteriorDatosEmpleo,
                                coloniaLocalidad:misOtrosEmpleosN[x][y].coloniaLocalidadDatosEmpleo,
                                municipioAlcaldia:{
                                    clave:misOtrosEmpleosN[x][y].municipioAlcaldiaClaveDatosEmpleo,
                                    valor:misOtrosEmpleosN[x][y].municipioAlcaldiaValorDatosEmpleo
                                },
                                entidadFederativa:{
                                    clave:misOtrosEmpleosN[x][y].entidadFederativaClaveDatosEmpleo,
                                    valor:misOtrosEmpleosN[x][y].entidadFederativaValorDatosEmpleo
                                },
                                codigoPostal:misOtrosEmpleosN[x][y].codigoPostalDatosEmpleo
                            },
                            domicilioExtranjero:{
                                calle:misOtrosEmpleosN[x][y].calleOficinaExtranjero,
                                numeroExterior:misOtrosEmpleosN[x][y].numeroExteriorExtranjeroDatosEmpleo,
                                numeroInterior:misOtrosEmpleosN[x][y].numeroInteriorExtranjeroDatosEmpleo,
                                coloniaLocalidad:misOtrosEmpleosN[x][y].ciudadLocalidadExtranjeroDatosEmpleo,
                                estadoProvincia:misOtrosEmpleosN[x][y].estadoProvinciaExtranjeroDatosEmpleo,
                                pais:misOtrosEmpleosN[x][y].paisDatosEmpleo,
                                codigoPostal:misOtrosEmpleosN[x][y].codigoPostalExtranjeroDatosEmpleo
                            },
                            aclaracionesObservaciones:misOtrosEmpleosN[x][y].aclaracionesObersvacionesDatosEmpleo
                        })
                    }
                    misOtrosEmpleosAux[x]=misOtrosEmpleos
                    misOtrosEmpleos=[]
                }
                            
//FIN Ordenamiento de otrosEmpleoCargoComision

                misExperienciasPublicasN=[]
                misExperienciasPrivadasN=[]

                for(let j in rows){
                    var queryMisExperienciasPublicasN = await getResult("select * from experiencialaboralpublica_n where ID_declarante = '"+rows[j].declarante_ID+"' ")
                    misExperienciasPublicasN[j]=(typeof queryMisExperienciasPublicasN !== 'undefined' && queryMisExperienciasPublicasN)?queryMisExperienciasPublicasN:{}
                
                    var queryMisExperienciasPrivadasN = await getResult("select * from experiencialaboralprivada_n where ID_declarante = '"+rows[j].declarante_ID+"' ")
                    misExperienciasPrivadasN[j]=(typeof queryMisExperienciasPrivadasN !== 'undefined' && queryMisExperienciasPrivadasN)?queryMisExperienciasPrivadasN:{}
                }

//INICIO Ordenamiento de experienciaLaboral
                        
                misExperienciasPublicas=[]
                misExperienciasPublicasAux=[]
                misExperienciasPrivadas=[]
                misExperienciasPrivadasAux=[]
            
                for(let x in misExperienciasPublicasN){
                    for(let y in misExperienciasPublicasN[x]){
                        misExperienciasPublicas.push({
                            tipoOperacion:misExperienciasPublicasN[x][y].operacion,
                            ambitoSector:{
                                clave:misExperienciasPublicasN[x][y].ambitoSectorClave,
                                valor:misExperienciasPublicasN[x][y].ambitoSectorValor
                            },
                            nivelOrdenGobierno:misExperienciasPublicasN[x][y].nivelOrdenGobierno,
                            ambitoPublico:misExperienciasPublicasN[x][y].ambitoPublico,
                            nombreEntePublico:misExperienciasPublicasN[x][y].nombreEntePublico,
                            areaAdscripcion:misExperienciasPublicasN[x][y].areaAdscripcion,
                            empleoCargoComision:misExperienciasPublicasN[x][y].empleoCargoComision,
                            funcionPrincipal:misExperienciasPublicasN[x][y].funcionPrincipal,
                            fechaIngreso:formatFecha(misExperienciasPublicasN[x][y].fechaIngreso),
                            fechaEgreso:formatFecha(misExperienciasPublicasN[x][y].fechaEgreso),
                            ubicacion:misExperienciasPublicasN[x][y].ubicacion
                        })
                    }
                    misExperienciasPublicasAux[x]=misExperienciasPublicas
                    misExperienciasPublicas=[]
                }
                    
                for(let x in misExperienciasPrivadasN){
                    for(let y in misExperienciasPrivadasN[x]){
                        misExperienciasPrivadas.push({
                            tipoOperacion:misExperienciasPrivadasN[x][y].operacion,
                            ambitoSector:{
                                clave:misExperienciasPrivadasN[x][y].ambitoSectorClave,
                                valor:misExperienciasPrivadasN[x][y].ambitoSectorValor
                            },
                            nombreEmpresaSociedadAsociacion:misExperienciasPrivadasN[x][y].nombreEmpresaSocialAsociacion,
                            rfc:misExperienciasPrivadasN[x][y].rfc,
                            area:misExperienciasPrivadasN[x][y].area,
                            puesto:misExperienciasPrivadasN[x][y].puesto,
                            sector:{
                                clave:misExperienciasPrivadasN[x][y].sectorClave,
                                valor:misExperienciasPrivadasN[x][y].sectorValor
                            },
                            fechaIngreso:formatFecha(misExperienciasPrivadasN[x][y].fechaIngreso),
                            fechaEgreso:formatFecha(misExperienciasPrivadasN[x][y].fechaEgreso),
                            ubicacion:misExperienciasPrivadasN[x][y].ubicacion
                        })
                    }
                    misExperienciasPrivadasAux[x]=misExperienciasPrivadas
                    misExperienciasPrivadas=[]
                }
                            
//FIN Ordenamiento de experienciaLaboral

                misDependientesEconomicosN=[]

                for(let j in rows){
                    var queryMisDependientesEconomicosN = await getResult("select * from datosdependienteeconomico_n where ID_declarante = '"+rows[j].declarante_ID+"' ")
                    misDependientesEconomicosN[j]=(typeof queryMisDependientesEconomicosN !== 'undefined' && queryMisDependientesEconomicosN)?queryMisDependientesEconomicosN:{}
                }

//INICIO Ordenamiento de dependientesEconomicos
                        
                misDependientesEconomicos=[]
                misDependientesEconomicosAux=[]
        
                for(let x in misDependientesEconomicosN){
                    for(let y in misDependientesEconomicosN[x]){
                        misDependientesEconomicos.push({
                            tipoOperacion:misDependientesEconomicosN[x][y].operacion,
                            nombre:misDependientesEconomicosN[x][y].nombreDependiente,
                            primerApellido:misDependientesEconomicosN[x][y].primerApellido,
                            segundoApellido:misDependientesEconomicosN[x][y].segundoApellido,
                            fechaNacimiento:formatFecha(misDependientesEconomicosN[x][y].fechaNacimiento),
                            rfc:misDependientesEconomicosN[x][y].RFC,
                            parentescoRelacion:{
                                clave:misDependientesEconomicosN[x][y].parentesRlecaionClave,
                                valor:misDependientesEconomicosN[x][y].parentesValor
                            },
                            extranjero:(misDependientesEconomicosN[x][y].extranjero)?true:false,
                            curp:misDependientesEconomicosN[x][y].curp,
                            habitaDomicilioDeclarante:(misDependientesEconomicosN[x][y].habitaDomicilioDeclarante)?true:false,
                            lugarDondeReside:misDependientesEconomicosN[x][y].lugarDondeReside,
                            domicilioMexico:{
                                calle:misDependientesEconomicosN[x][y].domicilioCalle,
                                numeroExterior:misDependientesEconomicosN[x][y].numeroExterior,
                                numeroInterior:misDependientesEconomicosN[x][y].numeroInterior,
                                coloniaLocalidad:misDependientesEconomicosN[x][y].coloniaLocalidad,
                                municipioAlcaldia:{
                                    clave:misDependientesEconomicosN[x][y].municipioAlcaldia,
                                    valor:misDependientesEconomicosN[x][y].valor
                                },
                                entidadFederativa:{
                                    clave:misDependientesEconomicosN[x][y].entidadFederativaClave,
                                    valor:misDependientesEconomicosN[x][y].entidadFederativaValor
                                },
                                codigoPostal:misDependientesEconomicosN[x][y].codigoPostal
                            },
                            domicilioExtranjero:{
                                calle:misDependientesEconomicosN[x][y].calleExtranjero,
                                numeroExterior:misDependientesEconomicosN[x][y].numeroExteriorExtranjero,
                                numeroInterior:misDependientesEconomicosN[x][y].numeroInteriorExtranjero,
                                coloniaLocalidad:misDependientesEconomicosN[x][y].ciudadLocalidadExtranjero,
                                estadoProvincia:misDependientesEconomicosN[x][y].estadoProvinciaExtranjero,
                                pais:misDependientesEconomicosN[x][y].paisExtranjero,
                                codigoPostal:misDependientesEconomicosN[x][y].codigoPostalExtranjero
                            },
                            actividadLaboral:{
                                clave:misDependientesEconomicosN[x][y].actividadLaboralClave,
                                valor:misDependientesEconomicosN[x][y].actividdLaboralValor
                            },
                            actividadLaboralSectorPublico:{
                                nivelOrdenGobierno:misDependientesEconomicosN[x][y].nivelOrdenGobierno,
                                ambitoPublico:misDependientesEconomicosN[x][y].ambitoPublico,
                                nombreEntePublico:misDependientesEconomicosN[x][y].nombreEntePublico,
                                areaAdscripcion:misDependientesEconomicosN[x][y].areaAscripcion,
                                empleoCargoComision:misDependientesEconomicosN[x][y].empleoCargoComision,
                                funcionPrincipal:misDependientesEconomicosN[x][y].funcionPrincipal,
                                salarioMensualNeto:{
                                    valor:misDependientesEconomicosN[x][y].salarioMensualNetoValor,
                                    moneda:misDependientesEconomicosN[x][y].salarioMensualNetoMoneda
                                },
                                fechaIngreso:formatFecha(misDependientesEconomicosN[x][y].fechaIngresoEmpleo)
                            },
                            actividadLaboralSectorPrivadoOtro:{
                                nombreEmpresaSociedadAsociacion:misDependientesEconomicosN[x][y].nombreEmpresaSociedadAsociacion,
                                rfc:misDependientesEconomicosN[x][y].rfcEmpresa,
                                empleoCargo:misDependientesEconomicosN[x][y].empleoCargo,
                                fechaIngreso:formatFecha(misDependientesEconomicosN[x][y].fechaIngresoEmpleoPrivado),
                                salarioMensualNeto:{
                                    valor:misDependientesEconomicosN[x][y].salarioNetoPrivado,
                                    moneda:misDependientesEconomicosN[x][y].salarioNetoMoneda
                                }
                            },
                            proveedorContratistaGobierno:(misDependientesEconomicosN[x][y].proveedorContratistaGobierno)?true:false,
                            sector:{
                                clave:misDependientesEconomicosN[x][y].sectorClave,
                                valor:misDependientesEconomicosN[x][y].sectorValor
                            }
                        })
                    }
                    misDependientesEconomicosAux[x]=misDependientesEconomicos
                    misDependientesEconomicos=[]
                }
//FIN Ordenamiento de dependientesEconomicos
                            
                misIngresosIndustrialesN=[]
                misIngresosFinancierosN=[]
                misIngresosEnajenacionesN=[]
                misIngresosProfesionalesN=[]
                misIngresosOtrosN=[]
                
                for(let j in rows){
                    var queryMisIngresosIndustrialesN = await getResult("select * from ingresoactividadindustrial_n where ID_declarante = '"+rows[j].declarante_ID+"' ")
                    misIngresosIndustrialesN[j]=(typeof queryMisIngresosIndustrialesN !== 'undefined' && queryMisIngresosIndustrialesN)?queryMisIngresosIndustrialesN:{}

                    var queryMisIngresosFinancierosN = await getResult("select * from ingresoactividadfinanciera_n where ID_declarante = '"+rows[j].declarante_ID+"' ")
                    misIngresosFinancierosN[j]=(typeof queryMisIngresosFinancierosN !== 'undefined' && queryMisIngresosFinancierosN)?queryMisIngresosFinancierosN:{}

                    var queryMisIngresosEnajenacionesN = await getResult("select * from ingresoenajenacionbien_n where ID_declarante = '"+rows[j].declarante_ID+"' ")
                    misIngresosEnajenacionesN[j]=(typeof queryMisIngresosEnajenacionesN !== 'undefined' && queryMisIngresosEnajenacionesN)?queryMisIngresosEnajenacionesN:{}

                    var queryMisIngresosProfesionalesN = await getResult("select * from ingresoservicioprofesional_n where ID_declarante = '"+rows[j].declarante_ID+"' ")
                    misIngresosProfesionalesN[j]=(typeof queryMisIngresosProfesionalesN !== 'undefined' && queryMisIngresosProfesionalesN)?queryMisIngresosProfesionalesN:{}

                    var queryMisIngresosOtrosN = await getResult("select * from ingresootroingreso_n where ID_declarante = '"+rows[j].declarante_ID+"' ")
                    misIngresosOtrosN[j]=(typeof queryMisIngresosOtrosN !== 'undefined' && queryMisIngresosOtrosN)?queryMisIngresosOtrosN:{}
                }

//INICIO Ordenamiento de ingresos

                misIngresosIndustriales=[]
                misIngresosIndustrialesAux=[]
        
                for(let x in misIngresosIndustrialesN){
                    for(let y in misIngresosIndustrialesN[x]){
                        misIngresosIndustriales.push({
                            remuneracion:{
                                valor:misIngresosIndustrialesN[x][y].actividadIndustrialValor,
                                moneda:misIngresosIndustrialesN[x][y].actividadIndustrialMoneda
                            },
                            nombreRazonSocial:misIngresosIndustrialesN[x][y].nombreRazonSocial,
                            tipoNegocio:misIngresosIndustrialesN[x][y].tipoNegocio
                        })
                    }

                    misIngresosIndustrialesAux[x]=misIngresosIndustriales
                    misIngresosIndustriales=[]
                }

                misIngresosFinancieros=[]
                misIngresosFinancierosAux=[]
    
                for(let x in misIngresosFinancierosN){
                    for(let y in misIngresosFinancierosN[x]){
                        misIngresosFinancieros.push({
                            remuneracion:{
                                valor:misIngresosFinancierosN[x][y].actividadFinancieraValor,
                                moneda:misIngresosFinancierosN[x][y].actividadFinancieraMoneda
                            },
                            tipoInstrumento:{
                                clave:misIngresosFinancierosN[x][y].tipoInstrumentoClave,
                                valor:misIngresosFinancierosN[x][y].tipoInstrumentoValor
                            }
                        
                        })
                    }
                    misIngresosFinancierosAux[x]=misIngresosFinancieros
                    misIngresosFinancieros=[]
                }

                misIngresosEnajenaciones=[]
                misIngresosEnajenacionesAux=[]
    
                for(let x in misIngresosEnajenacionesN){
                    for(let y in misIngresosEnajenacionesN[x]){
                        misIngresosEnajenaciones.push({
                            remuneracion:{
                                valor:misIngresosEnajenacionesN[x][y].enajenacionBienValor,
                                moneda:misIngresosEnajenacionesN[x][y].enajenacionBienMoneda
                            },
                            tipoBienEnajenado:misIngresosEnajenacionesN[x][y].tipoBienEnajenado
                        })
                    }
                    misIngresosEnajenacionesAux[x]=misIngresosEnajenaciones
                    misIngresosEnajenaciones=[]
                }

                misIngresosProfesionales=[]
                misIngresosProfesionalesAux=[]
    
                for(let x in misIngresosProfesionalesN){
                    for(let y in misIngresosProfesionalesN[x]){
                        misIngresosProfesionales.push({
                            remuneracion:{
                                valor:misIngresosProfesionalesN[x][y].servicioProfesionalValor,
                                moneda:misIngresosProfesionalesN[x][y].servicioProfesionalMoneda
                            },
                            tipoServicio:misIngresosProfesionalesN[x][y].tipoServicioProfesional
                        })
                    }
                    misIngresosProfesionalesAux[x]=misIngresosProfesionales
                    misIngresosProfesionales=[]
                }
            
                misIngresosOtros=[]
                misIngresosOtrosAux=[]
    
                for(let x in misIngresosOtrosN){
                    for(let y in misIngresosOtrosN[x]){
                        misIngresosOtros.push({
                            remuneracion:{
                                valor:misIngresosOtrosN[x][y].otroIngresoValor,
                                moneda:misIngresosOtrosN[x][y].otroIngresoMoneda
                            },
                            tipoIngreso:misIngresosOtrosN[x][y].tipoIngreso
                        })
                    }
                    misIngresosOtrosAux[x]=misIngresosOtros
                    misIngresosOtros=[]
                }

//FIN Ordenamiento de ingresos

                misIngresosIndustrialesAnioAntN=[]
                misIngresosFinancierosAnioAntN=[]
                misIngresosEnajenacionesAnioAntN=[]
                misIngresosProfesionalesAnioAntN=[]
                misIngresosOtrosAnioAntN=[]

                for(let j in rows){
                    var queryMisIngresosIndustrialesAnioAntN = await getResult("select * from actividadanteriorindustrial_n where ID_declarante = '"+rows[j].declarante_ID+"' ")
                    misIngresosIndustrialesAnioAntN[j]=(typeof queryMisIngresosIndustrialesAnioAntN !== 'undefined' && queryMisIngresosIndustrialesAnioAntN)?queryMisIngresosIndustrialesAnioAntN:{}

                    var queryMisIngresosFinancierosAnioAntN = await getResult("select * from actividadanteriorfinanciera_n where ID_declarante = '"+rows[j].declarante_ID+"' ")
                    misIngresosFinancierosAnioAntN[j]=(typeof queryMisIngresosFinancierosAnioAntN !== 'undefined' && queryMisIngresosFinancierosAnioAntN)?queryMisIngresosFinancierosAnioAntN:{}

                    var queryMisIngresosEnajenacionesAnioAntN = await getResult("select * from actividadanteriorenajenacionbien_n where ID_declarante = '"+rows[j].declarante_ID+"' ")
                    misIngresosEnajenacionesAnioAntN[j]=(typeof queryMisIngresosEnajenacionesAnioAntN !== 'undefined' && queryMisIngresosEnajenacionesAnioAntN)?queryMisIngresosEnajenacionesAnioAntN:{}

                    var queryMisIngresosProfesionalesAnioAntN = await getResult("select * from actividadanteriorservicioprofesional_n where ID_declarante = '"+rows[j].declarante_ID+"' ")
                    misIngresosProfesionalesAnioAntN[j]=(typeof queryMisIngresosProfesionalesAnioAntN !== 'undefined' && queryMisIngresosProfesionalesAnioAntN)?queryMisIngresosProfesionalesAnioAntN:{}

                    var queryMisIngresosOtrosAnioAntN = await getResult("select * from actividadanteriorotroingreso_n where ID_declarante = '"+rows[j].declarante_ID+"' ")
                    misIngresosOtrosAnioAntN[j]=(typeof queryMisIngresosOtrosAnioAntN !== 'undefined' && queryMisIngresosOtrosAnioAntN)?queryMisIngresosOtrosAnioAntN:{}
                }

//INICIO Ordenamiento de actividadAnualAnterior

                misIngresosIndustrialesAnioAnt=[]
                misIngresosIndustrialesAnioAntAux=[]
        
                for(let x in misIngresosIndustrialesAnioAntN){
                    for(let y in misIngresosIndustrialesAnioAntN[x]){
                        misIngresosIndustrialesAnioAnt.push({
                            remuneracion:{
                                valor:misIngresosIndustrialesAnioAntN[x][y].actividadIndustrialValor,
                                moneda:misIngresosIndustrialesAnioAntN[x][y].actividadIndustrialMoneda
                            },
                            nombreRazonSocial:misIngresosIndustrialesAnioAntN[x][y].nombreRazonSocial,
                            tipoNegocio:misIngresosIndustrialesAnioAntN[x][y].tipoNegocio
                    
                        })
                    }
                    misIngresosIndustrialesAnioAntAux[x]=misIngresosIndustrialesAnioAnt
                    misIngresosIndustrialesAnioAnt=[]
                }

                misIngresosFinancierosAnioAnt=[]
                misIngresosFinancierosAnioAntAux=[]
    
                for(let x in misIngresosFinancierosAnioAntN){
                    for(let y in misIngresosFinancierosAnioAntN[x]){
                        misIngresosFinancierosAnioAnt.push({
                            remuneracion:{
                                valor:misIngresosFinancierosAnioAntN[x][y].actividadFinancieraValor,
                                moneda:misIngresosFinancierosAnioAntN[x][y].actividadFinancieraMoneda
                            },
                            tipoInstrumento:{
                                clave:misIngresosFinancierosAnioAntN[x][y].tipoInstrumentoClave,
                                valor:misIngresosFinancierosAnioAntN[x][y].tipoInstrumentoValor
                            }
                        
                        })
                    }
                    misIngresosFinancierosAnioAntAux[x]=misIngresosFinancierosAnioAnt
                    misIngresosFinancierosAnioAnt=[]
                }

                misIngresosEnajenacionesAnioAnt=[]
                misIngresosEnajenacionesAnioAntAux=[]
    
                for(let x in misIngresosEnajenacionesAnioAntN){
                    for(let y in misIngresosEnajenacionesAnioAntN[x]){
                        misIngresosEnajenacionesAnioAnt.push({
                            remuneracion:{
                                valor:misIngresosEnajenacionesAnioAntN[x][y].enajenacionBienValor,
                                moneda:misIngresosEnajenacionesAnioAntN[x][y].enajenacionBienMoneda
                            },
                            tipoBienEnajenado:misIngresosEnajenacionesAnioAntN[x][y].tipoBienEnajenado
                        })
                    }
                    misIngresosEnajenacionesAnioAntAux[x]=misIngresosEnajenacionesAnioAnt
                    misIngresosEnajenacionesAnioAnt=[]
                }
            
                misIngresosProfesionalesAnioAnt=[]
                misIngresosProfesionalesAnioAntAux=[]
    
                for(let x in misIngresosProfesionalesAnioAntN){
                    for(let y in misIngresosProfesionalesAnioAntN[x]){
                        misIngresosProfesionalesAnioAnt.push({
                            remuneracion:{
                                valor:misIngresosProfesionalesAnioAntN[x][y].servicioProfesionalValor,
                                moneda:misIngresosProfesionalesAnioAntN[x][y].servicioProfesionalMoneda
                            },
                            tipoServicio:misIngresosProfesionalesAnioAntN[x][y].tipoServicioProfesional
                        })
                    }   
                    misIngresosProfesionalesAnioAntAux[x]=misIngresosProfesionalesAnioAnt
                    misIngresosProfesionalesAnioAnt=[]
                }
            
                misIngresosOtrosAnioAnt=[]
                misIngresosOtrosAnioAntAux=[]
    
                for(let x in misIngresosOtrosAnioAntN){
                    for(let y in misIngresosOtrosAnioAntN[x]){
                        misIngresosOtrosAnioAnt.push({
                            remuneracion:{
                                valor:misIngresosOtrosAnioAntN[x][y].otroIngresoValor,
                                moneda:misIngresosOtrosAnioAntN[x][y].otroIngresoMoneda
                            },
                            tipoIngreso:misIngresosOtrosAnioAntN[x][y].tipoIngreso
                        })
                    }
                    misIngresosOtrosAnioAntAux[x]=misIngresosOtrosAnioAnt
                    misIngresosOtrosAnioAnt=[]
                }
                            
//FIN Ordenamiento de actividadAnualAnterior

                misBienesInmueblesN=[]
                misBienesInmueblesTitularesN=[]
                misBienesInmueblesTercerosN=[]
                misBienesInmueblesTransmisoresN=[]

                for(let j in rows){
                    var queryMisBienesInmueblesN = await getResult("select * from bienesinmuebles_n where ID_declarante = '"+rows[j].declarante_ID+"' ")
                    misBienesInmueblesN[j]=(typeof queryMisBienesInmueblesN !== 'undefined' && queryMisBienesInmueblesN)?queryMisBienesInmueblesN:{}

                    for(let k in misBienesInmueblesN[j]){
                        var queryMisBienesInmueblesTitularesN = await getResult("select clave,valor from bieninmuebletitular_n where ID_declarante = '"+rows[j].declarante_ID+"' and ID_bienInmueble = '"+misBienesInmueblesN[j][k].ID_bienInmueble+"'")
                        misBienesInmueblesTitularesN[j]=(typeof queryMisBienesInmueblesTitularesN !== 'undefined' && queryMisBienesInmueblesTitularesN)?queryMisBienesInmueblesTitularesN:{}
                    }

                    for(let k in misBienesInmueblesN[j]){
                        var queryMisBienesInmueblesTercerosN = await getResult("select tipoPersona,nombreRazonSocial,rfc from bieninmuebletercero_n where ID_declarante = '"+rows[j].declarante_ID+"' and ID_bienInmueble = '"+misBienesInmueblesN[j][k].ID_bienInmueble+"'")
                        misBienesInmueblesTercerosN[j]=(typeof queryMisBienesInmueblesTercerosN !== 'undefined' && queryMisBienesInmueblesTercerosN)?queryMisBienesInmueblesTercerosN:{}
                    }

                    for(let k in misBienesInmueblesN[j]){
                        var queryMisBienesInmueblesTransmisoresN = await getResult("select * from bieninmuebletransmisor_n where ID_declarante = '"+rows[j].declarante_ID+"' and ID_bienInmueble = '"+misBienesInmueblesN[j][k].ID_bienInmueble+"'")
                        misBienesInmueblesTransmisoresN[j]=(typeof queryMisBienesInmueblesTransmisoresN !== 'undefined' && queryMisBienesInmueblesTransmisoresN)?queryMisBienesInmueblesTransmisoresN:{}
                    }
                }

//INICIO Ordenamiento de bienesInmuebles
                        
                misBienesInmuebles=[]
                misBienesInmueblesAux=[]
                misBienesInmueblesTransmisores=[]
                misBienesInmueblesTransmisoresAux=[]
                
                for(let x in misBienesInmueblesTransmisoresN){
                    for(let y in misBienesInmueblesTransmisoresN[x]){
                        misBienesInmueblesTransmisores.push({
                            tipoPersona:misBienesInmueblesTransmisoresN[x][y].tipoPersona,
                            nombreRazonSocial:misBienesInmueblesTransmisoresN[x][y].nombreRazonSocial,
                            rfc:misBienesInmueblesTransmisoresN[x][y].rfc,
                            relacion:{
                                clave:misBienesInmueblesTransmisoresN[x][y].relacionClave,
                                valor:misBienesInmueblesTransmisoresN[x][y].relacionValor
                            }
                        })
                    }
                    misBienesInmueblesTransmisoresAux[x]=misBienesInmueblesTransmisores
                    misBienesInmueblesTransmisores=[]
                }
                    
                for(let x in misBienesInmueblesN){
                    for(let y in misBienesInmueblesN[x]){
                        misBienesInmuebles.push({
                            tipoOperacion:misBienesInmueblesN[x][y].operacion,
                            tipoInmueble:{
                                clave:misBienesInmueblesN[x][y].tipoInmuebleClave,
                                valor:misBienesInmueblesN[x][y].tipoInmuebleValor
                            },
                            titular:misBienesInmueblesTitularesN[x],
                            porcentajePropiedad:misBienesInmueblesN[x][y].porcentajePropiedad,
                            superficieTerreno:{
                                valor:misBienesInmueblesN[x][y].superficieTerrenoValor,
                                unidad:misBienesInmueblesN[x][y].superficieTerrenoUnidad
                            },
                            superficieConstruccion:{
                                valor:misBienesInmueblesN[x][y].superficieConstruccionValor,
                                unidad:misBienesInmueblesN[x][y].superficieConstruccionUnidad
                            },
                            tercero:misBienesInmueblesTercerosN[x],
                            transmisor:misBienesInmueblesTransmisoresAux[x],
                            formaAdquisicion:{
                                clave:misBienesInmueblesN[x][y].formaAdquisicionClave,
                                valor:misBienesInmueblesN[x][y].formaAdquisicionValor
                            },
                            formaPago:misBienesInmueblesN[x][y].formaPago,
                            valorAdquisicion:{
                                valor:misBienesInmueblesN[x][y].valorAdquisicionValor,
                                moneda:misBienesInmueblesN[x][y].valorAdquisicionMoneda
                            },
                            fechaAdquisicion:formatFecha(misBienesInmueblesN[x][y].fechaAdquisicion),
                            datoIdentificacion:misBienesInmueblesN[x][y].datoIdentificacion,
                            valorConformeA:misBienesInmueblesN[x][y].valorConformeA,
                            domicilioMexico:{
                            calle:misBienesInmueblesN[x][y].domicilioCalle,
                            numeroExterior:misBienesInmueblesN[x][y].numeroExterior,
                            numeroInterior:misBienesInmueblesN[x][y].numeroInterior,
                            coloniaLocalidad:misBienesInmueblesN[x][y].coloniaLocalidad,
                            municipioAlcaldia:{
                                clave:misBienesInmueblesN[x][y].municipioAlcaldiaClave,
                                valor:misBienesInmueblesN[x][y].municipioAlcaldiaValor
                            },
                            entidadFederativa:{
                                clave:misBienesInmueblesN[x][y].entidadFederativaClave,
                                valor:misBienesInmueblesN[x][y].entidadFederativaValor
                            },
                            codigoPostal:misBienesInmueblesN[x][y].codigoPostal
                            },
                            domicilioExtranjero:{
                                calle:misBienesInmueblesN[x][y].calleExtranjero,
                                numeroExterior:misBienesInmueblesN[x][y].numeroExteriorExtranjero,
                                numeroInterior:misBienesInmueblesN[x][y].numeroInteriorExtranjero,
                                coloniaLocalidad:misBienesInmueblesN[x][y].ciudadLocalidadExtranjero,
                                estadoProvincia:misBienesInmueblesN[x][y].estadoProvinciaExtranjero,
                                pais:misBienesInmueblesN[x][y].pais,
                                codigoPostal:misBienesInmueblesN[x][y].codigoPostalExtranjero
                            },
                            motivoBaja:{
                                clave:misBienesInmueblesN[x][y].motivoBajaClave,
                                valor:misBienesInmueblesN[x][y].motivoBajaValor
                            }
                        })
                    }
                    misBienesInmueblesAux[x]=misBienesInmuebles
                    misBienesInmuebles=[]
                }

//FIN Ordenamiento de bienesInmuebles

                misVehiculosN=[]
                misVehiculosTitularesN=[]
                misVehiculosTercerosN=[]
                misVehiculosTransmisoresN=[]

                for(let j in rows){
                    var queryMisVehiculosN = await getResult("select * from vehiculos_n where ID_declarante = '"+rows[j].declarante_ID+"' ")
                    misVehiculosN[j]=(typeof queryMisVehiculosN !== 'undefined' && queryMisVehiculosN)?queryMisVehiculosN:{}

                    for(let k in misVehiculosN[j]){
                    var queryMisVehiculosTitularesN = await getResult("select clave,valor from vehiculotitular_n where ID_declarante = '"+rows[j].declarante_ID+"' and ID_vehiculo = '"+misVehiculosN[j][k].ID_vehiculo+"'")
                    misVehiculosTitularesN[j]=(typeof queryMisVehiculosTitularesN !== 'undefined' && queryMisVehiculosTitularesN)?queryMisVehiculosTitularesN:{}
                    }

                    for(let k in misVehiculosN[j]){
                    var queryMisVehiculosTercerosN = await getResult("select tipoPersona,nombreRazonSocial,rfc from vehiculotercero_n where ID_declarante = '"+rows[j].declarante_ID+"' and ID_vehiculo = '"+misVehiculosN[j][k].ID_vehiculo+"'")
                    misVehiculosTercerosN[j]=(typeof queryMisVehiculosTercerosN !== 'undefined' && queryMisVehiculosTercerosN)?queryMisVehiculosTercerosN:{}
                    }

                    for(let k in misVehiculosN[j]){
                    var queryMisVehiculosTransmisoresN = await getResult("select * from vehiculotransmisor_n where ID_declarante = '"+rows[j].declarante_ID+"' and ID_vehiculo = '"+misVehiculosN[j][k].ID_vehiculo+"'")
                    misVehiculosTransmisoresN[j]=(typeof queryMisVehiculosTransmisoresN !== 'undefined' && queryMisVehiculosTransmisoresN)?queryMisVehiculosTransmisoresN:{}
                    }
                }

//INICIO Ordenamiento de vehiculos
                        
                misVehiculos=[]
                misVehiculosAux=[]
                misVehiculosTransmisores=[]
                misVehiculosTransmisoresAux=[]
                
                for(let x in misVehiculosTransmisoresN){
                    for(let y in misVehiculosTransmisoresN[x]){
                        misVehiculosTransmisores.push({
                            tipoPersona:misVehiculosTransmisoresN[x][y].tipoPersona,
                            nombreRazonSocial:misVehiculosTransmisoresN[x][y].nombreRazonSocial,
                            rfc:misVehiculosTransmisoresN[x][y].rfc,
                            relacion:{
                                clave:misVehiculosTransmisoresN[x][y].relacionClave,
                                valor:misVehiculosTransmisoresN[x][y].relacionValor
                            }
                        })
                    }
                    misVehiculosTransmisoresAux[x]=misVehiculosTransmisores
                    misVehiculosTransmisores=[]
                }
                
                for(let x in misVehiculosN){
                    for(let y in misVehiculosN[x]){
                        misVehiculos.push({
                            tipoOperacion:misVehiculosN[x][y].operacion,
                            tipoVehiculo:{
                                clave:misVehiculosN[x][y].tipoVehiculoClave,
                                valor:misVehiculosN[x][y].tipoVehiculoValor
                            },
                            titular:misVehiculosTitularesN[x],
                            transmisor:misVehiculosTransmisoresAux[x],
                            marca:misVehiculosN[x][y].marca,
                            modelo:misVehiculosN[x][y].modelo,
                            anio:misVehiculosN[x][y].anio,
                            numeroSerieRegistro:misVehiculosN[x][y].numeroSerieRegistro,
                            tercero:misVehiculosTercerosN[x],
                            lugarRegistro:{
                                pais:misVehiculosN[x][y].lugarRegistroPais,
                                entidadFederativa:{
                                clave:misVehiculosN[x][y].entidadFederativaClave,
                                valor:misVehiculosN[x][y].entidadFederativaValor
                                },
                            },
                            formaAdquisicion:{
                                clave:misVehiculosN[x][y].formaAdquisicionClave,
                                valor:misVehiculosN[x][y].formaAdquisicionValor
                            },
                            formaPago:misVehiculosN[x][y].formaPago,
                            valorAdquisicion:{
                                valor:misVehiculosN[x][y].valorAdquisicionValor,
                                moneda:misVehiculosN[x][y].valorAdquisicionMoneda
                            },
                            fechaAdquisicion:formatFecha(misVehiculosN[x][y].fechaAquisicion),
                            motivoBaja:{
                            clave:misVehiculosN[x][y].motivoBajaClave,
                            valor:misVehiculosN[x][y].motivoBajaValor
                            }
                        })
                    }
                    misVehiculosAux[x]=misVehiculos
                    misVehiculos=[]
                }

//FIN Ordenamiento de vehiculos
                                
                misBienesMueblesN=[]
                misBienesMueblesTitularesN=[]
                misBienesMueblesTercerosN=[]
                misBienesMueblesTransmisoresN=[]

                for(let j in rows){
                    var queryMisBienesMueblesN = await getResult("select * from bienesmuebles_n where ID_declarante = '"+rows[j].declarante_ID+"' ")
                    misBienesMueblesN[j]=(typeof queryMisBienesMueblesN !== 'undefined' && queryMisBienesMueblesN)?queryMisBienesMueblesN:{}
        
                    for(let k in misBienesMueblesN[j]){
                    var queryMisBienesMueblesTitularesN = await getResult("select clave,valor from bienmuebletitular_n where ID_declarante = '"+rows[j].declarante_ID+"' and ID_bienMueble = '"+misBienesMueblesN[j][k].ID_bienMueble+"'")
                    misBienesMueblesTitularesN[j]=(typeof queryMisBienesMueblesTitularesN !== 'undefined' && queryMisBienesMueblesTitularesN)?queryMisBienesMueblesTitularesN:{}
                    }

                    for(let k in misBienesMueblesN[j]){
                    var queryMisBienesMueblesTercerosN = await getResult("select tipoPersona,nombreRazonSocial,rfc from bienmuebletercero_n where ID_declarante = '"+rows[j].declarante_ID+"' and ID_bienMueble = '"+misBienesMueblesN[j][k].ID_bienMueble+"'")
                    misBienesMueblesTercerosN[j]=(typeof queryMisBienesMueblesTercerosN !== 'undefined' && queryMisBienesMueblesTercerosN)?queryMisBienesMueblesTercerosN:{}
                    }

                    for(let k in misBienesMueblesN[j]){
                    var queryMisBienesMueblesTransmisoresN = await getResult("select * from bienmuebletransmisor_n where ID_declarante = '"+rows[j].declarante_ID+"' and ID_bienMueble = '"+misBienesMueblesN[j][k].ID_bienMueble+"'")
                    misBienesMueblesTransmisoresN[j]=(typeof queryMisBienesMueblesTransmisoresN !== 'undefined' && queryMisBienesMueblesTransmisoresN)?queryMisBienesMueblesTransmisoresN:{}
                    }
                }

//INICIO Ordenamiento de bienesMuebles

                misBienesMuebles=[]
                misBienesMueblesAux=[]
                misBienesMueblesTransmisores=[]
                misBienesMueblesTransmisoresAux=[]
                
                for(let x in misBienesMueblesTransmisoresN){
                    for(let y in misBienesMueblesTransmisoresN[x]){
                        misBienesMueblesTransmisores.push({
                            tipoPersona:misBienesMueblesTransmisoresN[x][y].tipoPersona,
                            nombreRazonSocial:misBienesMueblesTransmisoresN[x][y].nombreRazonSocial,
                            rfc:misBienesMueblesTransmisoresN[x][y].rfc,
                            relacion:{
                                clave:misBienesMueblesTransmisoresN[x][y].relacionClave,
                                valor:misBienesMueblesTransmisoresN[x][y].relacionValor
                            }
                        })
                    }
                    misBienesMueblesTransmisoresAux[x]=misBienesMueblesTransmisores
                    misBienesMueblesTransmisores=[]
                }
                    
                for(let x in misBienesMueblesN){
                    for(let y in misBienesMueblesN[x]){
                        misBienesMuebles.push({
                            tipoOperacion:misBienesMueblesN[x][y].operacion,
                            titular:misBienesMueblesTitularesN[x],
                            tipoBien:{
                                clave:misBienesMueblesN[x][y].tipoBienClave,
                                valor:misBienesMueblesN[x][y].tipoBienValor
                            },
                            transmisor:misBienesMueblesTransmisoresAux[x],
                            tercero:misBienesMueblesTercerosN[x],
                            descripcionGeneralBien:misBienesMueblesN[x][y].descripcionGeneralBien,
                            formaAdquisicion:{
                                clave:misBienesMueblesN[x][y].formaAdquisicionClave,
                                valor:misBienesMueblesN[x][y].formaAdquisicionValor
                            },
                            formaPago:misBienesMueblesN[x][y].formaPago,
                            valorAdquisicion:{
                                valor:misBienesMueblesN[x][y].valorAdquisicionValor,
                                moneda:misBienesMueblesN[x][y].valorAdquisicionMoneda
                            },
                            fechaAdquisicion:formatFecha(misBienesMueblesN[x][y].fechaAdquisicion),
                            motivoBaja:{
                            clave:misBienesMueblesN[x][y].motivoBajaClave,
                            valor:misBienesMueblesN[x][y].motivoBajaValor
                            },
                        })
                    }
                    misBienesMueblesAux[x]=misBienesMuebles
                    misBienesMuebles=[]
                }

//FIN Ordenamiento de bienesMuebles
                
                misInversionesN=[]
                misInversionesTitularesN=[]
                misInversionesTercerosN=[]
                misInversionesTransmisoresN=[]

                for(let j in rows){
                    var queryMisInversionesN = await getResult("select * from inversionescuentasvalores_n where ID_declarante = '"+rows[j].declarante_ID+"' ")
                    misInversionesN[j]=(typeof queryMisInversionesN !== 'undefined' && queryMisInversionesN)?queryMisInversionesN:{}

                    for(let k in misInversionesN[j]){
                    var queryMisInversionesTitularesN = await getResult("select clave,valor from inversiontitular_n where ID_declarante = '"+rows[j].declarante_ID+"' and ID_inversion = '"+misInversionesN[j][k].ID_inversion+"'")
                    misInversionesTitularesN[j]=(typeof queryMisInversionesTitularesN !== 'undefined' && queryMisInversionesTitularesN)?queryMisInversionesTitularesN:{}
                    }

                    for(let k in misInversionesN[j]){
                    var queryMisInversionesTercerosN = await getResult("select tipoPersona,nombreRazonSocial,rfc from inversiontercero_n where ID_declarante = '"+rows[j].declarante_ID+"' and ID_inversion = '"+misInversionesN[j][k].ID_inversion+"'")
                    misInversionesTercerosN[j]=(typeof queryMisInversionesTercerosN !== 'undefined' && queryMisInversionesTercerosN)?queryMisInversionesTercerosN:{}
                    }
                
                }

//INICIO Ordenamiento de inversionesCuentasValores

                misInversiones=[]
                misInversionesAux=[]
                
                for(let x in misInversionesN){
                    for(let y in misInversionesN[x]){
                        misInversiones.push((rows[x].tipoDeclaracion.toUpperCase().charAt(0)==I)?({
                            tipoOperacion:misInversionesN[x][y].operacion,
                            tipoInversion:{
                                clave:misInversionesN[x][y].tipoInversionClave,
                                valor:misInversionesN[x][y].tipoInversionValor
                            },
                            subTipoInversion:{
                                clave:misInversionesN[x][y].subTipoInversionClave,
                                valor:misInversionesN[x][y].subTipoInversionValor
                            },
                            titular:misInversionesTitularesN[x],
                            tercero:misInversionesTercerosN[x],
                            numeroCuentaContrato:misInversionesN[x][y].numeroCuentaContrato,
                            localizacionInversion:{
                                pais:misInversionesN[x][y].localizacionInversionPais,
                                institucionRazonSocial:misInversionesN[x][y].intitucionRazonSocial,
                                rfc:misInversionesN[x][y].rfc
                            },
                            saldoSituacionActual:{
                                valor:misInversionesN[x][y].saldoFechaValor,
                                moneda:misInversionesN[x][y].saldoFechaMoneda
                            },
                            porcentajeIncrementoDecremento:misInversionesN[x][y].porcentajeIncrementoDecremento
                        }):(rows[x].tipoDeclaracion.toUpperCase().charAt(0)==M)?({
                            tipoInversion:{
                                clave:misInversionesN[x][y].tipoInversionClave,
                                valor:misInversionesN[x][y].tipoInversionValor
                            },
                            subTipoInversion:{
                                clave:misInversionesN[x][y].subTipoInversionClave,
                                valor:misInversionesN[x][y].subTipoInversionValor
                            },
                            titular:misInversionesTitularesN[x],
                            tercero:misInversionesTercerosN[x],
                            numeroCuentaContrato:misInversionesN[x][y].numeroCuentaContrato,
                            localizacionInversion:{
                                pais:misInversionesN[x][y].localizacionInversionPais,
                                institucionRazonSocial:misInversionesN[x][y].intitucionRazonSocial,
                                rfc:misInversionesN[x][y].rfc
                            },
                            saldoDiciembreAnterior:{
                                valor:misInversionesN[x][y].saldoFechaValor,
                                moneda:misInversionesN[x][y].saldoFechaMoneda
                            },
                            porcentajeIncrementoDecremento:misInversionesN[x][y].porcentajeIncrementoDecremento
                        }):({
                            tipoInversion:{
                                clave:misInversionesN[x][y].tipoInversionClave,
                                valor:misInversionesN[x][y].tipoInversionValor
                            },
                            subTipoInversion:{
                                clave:misInversionesN[x][y].subTipoInversionClave,
                                valor:misInversionesN[x][y].subTipoInversionValor
                            },
                            titular:misInversionesTitularesN[x],
                            tercero:misInversionesTercerosN[x],
                            numeroCuentaContrato:misInversionesN[x][y].numeroCuentaContrato,
                            localizacionInversion:{
                                pais:misInversionesN[x][y].localizacionInversionPais,
                                institucionRazonSocial:misInversionesN[x][y].intitucionRazonSocial,
                                rfc:misInversionesN[x][y].rfc
                            },
                            saldoFechaConclusion:{
                                valor:misInversionesN[x][y].saldoFechaValor,
                                moneda:misInversionesN[x][y].saldoFechaMoneda
                            },
                            porcentajeIncrementoDecremento:misInversionesN[x][y].porcentajeIncrementoDecremento
                        }))
                    }
                    misInversionesAux[x]=misInversiones
                    misInversiones=[]
                }

//FIN Ordenamiento de inversionesCuentasValores
                                
                misAdeudosN=[]
                misAdeudosTitularesN=[]
                misAdeudosTercerosN=[]
                misAdeudosTransmisoresN=[]

                for(let j in rows){
                    var queryMisAdeudosN = await getResult("select * from adeudospasivos_n where ID_declarante = '"+rows[j].declarante_ID+"' ")
                    misAdeudosN[j]=(typeof queryMisAdeudosN !== 'undefined' && queryMisAdeudosN)?queryMisAdeudosN:{}

                    for(let k in misAdeudosN[j]){
                    var queryMisAdeudosTitularesN = await getResult("select clave,valor from adeudopasivotitular_n where ID_declarante = '"+rows[j].declarante_ID+"' and ID_adeudoPasivo = '"+misAdeudosN[j][k].ID_adeudoPasivo+"'")
                    misAdeudosTitularesN[j]=(typeof queryMisAdeudosTitularesN !== 'undefined' && queryMisAdeudosTitularesN)?queryMisAdeudosTitularesN:{}
                    }

                    for(let k in misAdeudosN[j]){
                    var queryMisAdeudosTercerosN = await getResult("select tipoPersona,nombreRazonSocial,rfc from adeudopasivotercero_n where ID_declarante = '"+rows[j].declarante_ID+"' and ID_adeudoPasivo = '"+misAdeudosN[j][k].ID_adeudoPasivo+"'")
                    misAdeudosTercerosN[j]=(typeof queryMisAdeudosTercerosN !== 'undefined' && queryMisAdeudosTercerosN)?queryMisAdeudosTercerosN:{}
                    }
                
                }
                                
//INICIO Ordenamiento de adeudosPasivos

                misAdeudos=[]
                misAdeudosAux=[]
                
                for(let x in misAdeudosN){
                    for(let y in misAdeudosN[x]){
                        misAdeudos.push((rows[x].tipoDeclaracion.toUpperCase().charAt(0)==I)?({
                            tipoOperacion:misAdeudosN[x][y].operacion,
                            titular:misAdeudosTitularesN[x],
                            tipoAdeudo:{
                                clave:misAdeudosN[x][y].tipoAdeudoClave,
                                valor:misAdeudosN[x][y].tipoAdeudoValor
                            },
                            numeroCuentaContrato:misAdeudosN[x][y].numeroCuentaContrato,
                            fechaAdquisicion:formatFecha(misAdeudosN[x][y].fechaAdquision),
                            montoOriginal:{
                                valor:misAdeudosN[x][y].montoOriginalValor,
                                moneda:misAdeudosN[x][y].montoOriginalMoneda
                            },
                            saldoInsolutoSituacionActual:{
                                valor:misAdeudosN[x][y].saldoInsolutoFechaConclusionValor,
                                moneda:misAdeudosN[x][y].saldoInsolutoFechaConclusionMoneda
                            },
                            tercero:misAdeudosTercerosN[x],
                            otorganteCredito:{
                                tipoPersona:misAdeudosN[x][y].otorganteCreditoTipoPersona,
                                nombreInstitucion:misAdeudosN[x][y].otorganteCreditoNombreInstitucion,
                                rfc:misAdeudosN[x][y].otorganteCreditoRFC
                            },
                            localizacionAdeudo:{
                                pais:misAdeudosN[x][y].localizacionAdeudoPais
                            }
                        }):(rows[x].tipoDeclaracion.toUpperCase().charAt(0)==M)?({
                            titular:misAdeudosTitularesN[x],
                            tipoAdeudo:{
                                clave:misAdeudosN[x][y].tipoAdeudoClave,
                                valor:misAdeudosN[x][y].tipoAdeudoValor
                            },
                            numeroCuentaContrato:misAdeudosN[x][y].numeroCuentaContrato,
                            fechaAdquisicion:formatFecha(misAdeudosN[x][y].fechaAdquision),
                            montoOriginal:{
                                valor:misAdeudosN[x][y].montoOriginalValor,
                                moneda:misAdeudosN[x][y].montoOriginalMoneda
                            },
                            saldoInsolutoDiciembreAnterior:{
                                valor:misAdeudosN[x][y].saldoInsolutoFechaConclusionValor,
                                moneda:misAdeudosN[x][y].saldoInsolutoFechaConclusionMoneda
                            },
                            porcentajeIncrementoDecremento:misAdeudosN[x][y].porcentajaIncrementoDecremento,
                            tercero:misAdeudosTercerosN[x],
                            otorganteCredito:{
                                tipoPersona:misAdeudosN[x][y].otorganteCreditoTipoPersona,
                                nombreInstitucion:misAdeudosN[x][y].otorganteCreditoNombreInstitucion,
                                rfc:misAdeudosN[x][y].otorganteCreditoRFC
                            },
                            localizacionAdeudo:{
                                pais:misAdeudosN[x][y].localizacionAdeudoPais
                            }
                        }):({
                            titular:misAdeudosTitularesN[x],
                            tipoAdeudo:{
                                clave:misAdeudosN[x][y].tipoAdeudoClave,
                                valor:misAdeudosN[x][y].tipoAdeudoValor
                            },
                            numeroCuentaContrato:misAdeudosN[x][y].numeroCuentaContrato,
                            fechaAdquisicion:formatFecha(misAdeudosN[x][y].fechaAdquision),
                            montoOriginal:{
                                valor:misAdeudosN[x][y].montoOriginalValor,
                                moneda:misAdeudosN[x][y].montoOriginalMoneda
                            },
                            saldoInsolutoFechaConclusion:{
                                valor:misAdeudosN[x][y].saldoInsolutoFechaConclusionValor,
                                moneda:misAdeudosN[x][y].saldoInsolutoFechaConclusionMoneda
                            },
                            porcentajeIncrementoDecremento:misAdeudosN[x][y].porcentajaIncrementoDecremento,
                            tercero:misAdeudosTercerosN[x],
                            otorganteCredito:{
                                tipoPersona:misAdeudosN[x][y].otorganteCreditoTipoPersona,
                                nombreInstitucion:misAdeudosN[x][y].otorganteCreditoNombreInstitucion,
                                rfc:misAdeudosN[x][y].otorganteCreditoRFC
                            },
                            localizacionAdeudo:{
                                pais:misAdeudosN[x][y].localizacionAdeudoPais
                            }
                        }))
                    }
                    misAdeudosAux[x]=misAdeudos
                    misAdeudos=[]
                }

//FIN Ordenamiento de adeudosPasivos

                misPrestamosN=[]

                for(let j in rows){
                    var queryMisPrestamosN = await getResult("select * from prestamocomodato_n where ID_declarante = '"+rows[j].declarante_ID+"' ")
                    misPrestamosN[j]=(typeof queryMisPrestamosN !== 'undefined' && queryMisPrestamosN)?queryMisPrestamosN:{}
                }
                                                           
//INICIO Ordenamiento de prestamoComodato

                misPrestamos=[]
                misPrestamosAux=[]
                
                for(let x in misPrestamosN){
                    for(let y in misPrestamosN[x]){
                        misPrestamos.push({
                            tipoOperacion:misPrestamosN[x][y].operacion,
                            tipoBien:{
                                inmueble:{
                                    tipoInmueble:{
                                        clave:misPrestamosN[x][y].tipoInmuebleClave,
                                        valor:misPrestamosN[x][y].tipoInmuebleValor
                                    },
                                    domicilioMexico:{
                                        calle:misPrestamosN[x][y].domicilioMexicoCalle,
                                        numeroExterior:misPrestamosN[x][y].numeroExterior,
                                        numeroInterior:misPrestamosN[x][y].numeroInterior,
                                        coloniaLocalidad:misPrestamosN[x][y].coloniaLocalidad,
                                        municipioAlcaldia:{
                                            clave:misPrestamosN[x][y].municipioAlcaldiaClave,
                                            valor:misPrestamosN[x][y].municipioAlcaldiaValor
                                        },
                                        entidadFederativa:{
                                            clave:misPrestamosN[x][y].entidadFederativaClave,
                                            valor:misPrestamosN[x][y].entidadFederativaValor
                                        },
                                        codigoPostal:misPrestamosN[x][y].codigoPostal
                                    },
                                    domicilioExtranjero:{
                                        calle:misPrestamosN[x][y].calleExtranjero,
                                        numeroExterior:misPrestamosN[x][y].numeroExteriorExtranjero,
                                        numeroInterior:misPrestamosN[x][y].numeroInteriorExtranjero,
                                        coloniaLocalidad:misPrestamosN[x][y].ciudadLocalidadExtranjero,
                                        estadoProvincia:misPrestamosN[x][y].estadoProvinciaExtranjero,
                                        pais:misPrestamosN[x][y].paisExtranjero,
                                        codigoPostal:misPrestamosN[x][y].codigoPostalExtranjero
                                    },
                                },
                                vehiculo:{
                                    tipo:{
                                        clave:misPrestamosN[x][y].vehiculoClave,
                                        valor:misPrestamosN[x][y].vehiculoValor
                                    },
                                    marca:misPrestamosN[x][y].marca,
                                    modelo:misPrestamosN[x][y].modelo,
                                    anio:misPrestamosN[x][y].anio,
                                    numeroSerieRegistro:misPrestamosN[x][y].numeroSerieRegistro,
                                    lugarRegistro:{
                                        pais:misPrestamosN[x][y].lugarRegistroPais,
                                        entidadFederativa:{
                                            clave:misPrestamosN[x][y].entidadFederativaClave2,
                                            valor:misPrestamosN[x][y].entidadFederativaValor2
                                        },
                                    }
                                }
                            },
                            duenoTitular:{
                                tipoDuenoTitular:misPrestamosN[x][y].tipoDuenoTitular,
                                nombreTitular:misPrestamosN[x][y].nombreTitular,
                                rfc:misPrestamosN[x][y].rfcTitular,
                                relacionConTitular:misPrestamosN[x][y].relacionConTitular
                            }
                        })
                    }
                    misPrestamosAux[x]=misPrestamos
                    misPrestamos=[]
                }

//FIN Ordenamiento de prestamoComodato

                misParticipacionesN=[]

                    for(let j in rows){
                        var queryMisParticipacionesN = await getResult("select * from participacion_n where ID_declarante = '"+rows[j].declarante_ID+"' ")
                        misParticipacionesN[j]=(typeof queryMisParticipacionesN !== 'undefined' && queryMisParticipacionesN)?queryMisParticipacionesN:{}
                    }
                                                           
//INICIO Ordenamiento de participacion

                misParticipaciones=[]
                misParticipacionesAux=[]
                            
                for(let x in misParticipacionesN){
                    for(let y in misParticipacionesN[x]){
                        misParticipaciones.push({
                            tipoOperacion:misParticipacionesN[x][y].operacion,
                            tipoRelacion:misParticipacionesN[x][y].tipoRelacion,
                            nombreEmpresaSociedadAsociacion:misParticipacionesN[x][y].nombreEmpresaSociedadAsociacion,
                            rfc:misParticipacionesN[x][y].rfc,
                            porcentajeParticipacion:misParticipacionesN[x][y].porcentajeParticipacion,
                            tipoParticipacion:{
                                clave:misParticipacionesN[x][y].tipoParticipacionClave,
                                valor:misParticipacionesN[x][y].tipoPaticipacionValor
                            },
                            recibeRemuneracion:(misParticipacionesN[x][y].recibeRemuneracion)?true:false,
                            montoMensual:{
                                valor:misParticipacionesN[x][y].montoMensualRemuneracionValor,
                                moneda:misParticipacionesN[x][y].montoMensualRemuneracionMoneda
                            },
                            ubicacion:{
                                pais:misParticipacionesN[x][y].ubicacionPais,
                                entidadFederativa:{
                                    clave:misParticipacionesN[x][y].entidadFederativaClave,
                                    valor:misParticipacionesN[x][y].entidadFederativaValor
                                }
                            },
                            sector:{
                                clave:misParticipacionesN[x][y].sectorClave,
                                valor:misParticipacionesN[x][y].sectorValor
                            }
                        })
                    }
                    misParticipacionesAux[x]=misParticipaciones
                    misParticipaciones=[]
                }

//FIN Ordenamiento de participacion

                misTomaDecisionesN=[]

                for(let j in rows){
                    var queryMisTomaDecisionesN = await getResult("select * from participaciontomadecisiones_n where ID_declarante = '"+rows[j].declarante_ID+"' ")
                    misTomaDecisionesN[j]=(typeof queryMisTomaDecisionesN !== 'undefined' && queryMisTomaDecisionesN)?queryMisTomaDecisionesN:{}
                }
                                                     
//INICIO Ordenamiento de participacionTomaDecisiones

                misTomaDecisiones=[]
                misTomaDecisionesAux=[]
                    
                for(let x in misTomaDecisionesN){
                    for(let y in misTomaDecisionesN[x]){
                        misTomaDecisiones.push({
                            tipoOperacion:misTomaDecisionesN[x][y].operacion,
                            tipoRelacion:misTomaDecisionesN[x][y].tipoRelacion,
                            tipoInstitucion:{
                                clave:misTomaDecisionesN[x][y].tipoInstitucionClave,
                                valor:misTomaDecisionesN[x][y].tipoInstitucionValor
                            },
                            nombreInstitucion:misTomaDecisionesN[x][y].nombreInstitucion,
                            rfc:misTomaDecisionesN[x][y].rfc,
                            puestoRol:misTomaDecisionesN[x][y].puestoRol,
                            fechaInicioParticipacion:formatFecha(misTomaDecisionesN[x][y].fechaInicioParticipacion),
                            recibeRemuneracion:(misTomaDecisionesN[x][y].recibeRemuneracion)?true:false,
                            montoMensual:{
                                valor:misTomaDecisionesN[x][y].montoMensualValor,
                                moneda:misTomaDecisionesN[x][y].montoMensualMoneda
                            },
                            ubicacion:{
                                pais:misTomaDecisionesN[x][y].pais,
                                entidadFederativa:{
                                    clave:misTomaDecisionesN[x][y].entidadFederativaClave,
                                    valor:misTomaDecisionesN[x][y].entidadFederativaValor
                                }
                            }
                        })
                    }
                    misTomaDecisionesAux[x]=misTomaDecisiones
                    misTomaDecisiones=[]
                }

//FIN Ordenamiento de participacionTomaDecisiones

                misApoyosN=[]

                for(let j in rows){
                    var queryMisApoyosN = await getResult("select * from apoyos_n where ID_declarante = '"+rows[j].declarante_ID+"' ")
                    misApoyosN[j]=(typeof queryMisApoyosN !== 'undefined' && queryMisApoyosN)?queryMisApoyosN:{}
                }
                                                     
//INICIO Ordenamiento de apoyos

                misApoyos=[]
                misApoyosAux=[]
                    
                for(let x in misApoyosN){
                    for(let y in misApoyosN[x]){
                        misApoyos.push({
                            tipoOperacion:misApoyosN[x][y].operacion,
                            tipoPersona:misApoyosN[x][y].tipoPersona,
                            beneficiarioPrograma:{
                                clave:misApoyosN[x][y].beneficiarioProgramaClave,
                                valor:misApoyosN[x][y].beneficiarioProgramaValor
                            },
                            nombrePrograma:misApoyosN[x][y].nombrePrograma,
                            institucionOtorgante:misApoyosN[x][y].institucionOtorgante,
                            nivelOrdenGobierno:misApoyosN[x][y].nivelOrdenGobierno,
                            tipoApoyo:{
                                clave:misApoyosN[x][y].tipoApoyoClave,
                                valor:misApoyosN[x][y].tipoApoyoValor
                            },
                            formaRecepcion:misApoyosN[x][y].fotmaRecepcion,
                            montoApoyoMensual:{
                                valor:misApoyosN[x][y].montoMensualValor,
                                moneda:misApoyosN[x][y].montoMensualMoneda
                            },
                            especifiqueApoyo:misApoyosN[x][y].especifiqueApoyo
                        })
                    }
                    misApoyosAux[x]=misApoyos
                    misApoyos=[]
                }

//FIN Ordenamiento de apoyos

                misRepresentacionesN=[]

                for(let j in rows){
                    var queryMisRepresentacionesN = await getResult("select * from representaciones_n where ID_declarante = '"+rows[j].declarante_ID+"' ")
                    misRepresentacionesN[j]=(typeof queryMisRepresentacionesN !== 'undefined' && queryMisRepresentacionesN)?queryMisRepresentacionesN:{}
                }
                                                     
//INICIO Ordenamiento de representaciones

                misRepresentaciones=[]
                misRepresentacionesAux=[]
                    
                for(let x in misRepresentacionesN){
                    for(let y in misRepresentacionesN[x]){
                        misRepresentaciones.push({
                            tipoOperacion:misRepresentacionesN[x][y].operacion,
                            tipoRelacion:misRepresentacionesN[x][y].tipoRelacion,
                            tipoRepresentacion:misRepresentacionesN[x][y].tipoRepresentacion,
                            fechaInicioRepresentacion:formatFecha(misRepresentacionesN[x][y].fechaInicioRepresentacion),
                            tipoPersona:misRepresentacionesN[x][y].tipoPersona,
                            nombreRazonSocial:misRepresentacionesN[x][y].nombreRazonSocial,
                            rfc:misRepresentacionesN[x][y].rfc,
                            recibeRemuneracion:(misRepresentacionesN[x][y].recibeRemuneracion)?true:false,
                            montoMensual:{
                                valor:misRepresentacionesN[x][y].montoMensualValor,
                                moneda:misRepresentacionesN[x][y].montoMensualMoneda
                            },
                            ubicacion:{
                                pais:misRepresentacionesN[x][y].pais,
                                entidadFederativa:{
                                    clave:misRepresentacionesN[x][y].entidadFederativaClave,
                                    valor:misRepresentacionesN[x][y].entidadFederativaValor
                                }
                            },
                            sector:{
                                clave:misRepresentacionesN[x][y].sectorClave,
                                valor:misRepresentacionesN[x][y].sectorValor
                            }
                        })
                    }
                    misRepresentacionesAux[x]=misRepresentaciones
                    misRepresentaciones=[]
                }

//FIN Ordenamiento de representaciones

                misClientesN=[]

                for(let j in rows){
                    var queryMisClientesN = await getResult("select * from clientesprincipales_n where ID_declarante = '"+rows[j].declarante_ID+"' ")
                    misClientesN[j]=(typeof queryMisClientesN !== 'undefined' && queryMisClientesN)?queryMisClientesN:{}
                }
                                                     
//INICIO Ordenamiento de clientesPrincipales

                misClientes=[]
                misClientesAux=[]
                    
                for(let x in misClientesN){
                    for(let y in misClientesN[x]){
                        misClientes.push({
                            tipoOperacion:misClientesN[x][y].operacion,
                            realizaActividadLucrativa:(misClientesN[x][y].realizaActividadLucrativa)?true:false,
                            tipoRelacion:misClientesN[x][y].tipoRelacion,
                            empresa:{
                                nombreEmpresaServicio:misClientesN[x][y].nombreEmpresaServicio,
                                rfc:misClientesN[x][y].rfcEmpresa,
                            },
                            clientePrincipal:{
                                tipoPersona:misClientesN[x][y].clientePrincipalTipoPersona,
                                nombreRazonSocial:misClientesN[x][y].clienteRazonSocial,
                                rfc:misClientesN[x][y].clienteRFC,
                            },
                            sector:{
                                clave:misClientesN[x][y].sectorClave,
                                valor:misClientesN[x][y].sectorValor
                            },
                            montoAproximadoGanancia:{
                                valor:misClientesN[x][y].montoAproximadoGananciaValor,
                                moneda:misClientesN[x][y].montoAproximadoGananciaMoneda
                            },
                            ubicacion:{
                                pais:misClientesN[x][y].pais,
                                entidadFederativa:{
                                    clave:misClientesN[x][y].entidadFederativaClave,
                                    valor:misClientesN[x][y].entidadFederativaValor
                                }
                            }
                        })
                    }
                    misClientesAux[x]=misClientes
                    misClientes=[]
                }

//FIN Ordenamiento de clientesPrincipales

                misBeneficiosN=[]
                misBeneficiosBeneficiariosN=[]

                for(let j in rows){
                    var queryMisBeneficiosN = await getResult("select * from beneficiosprivados_n where ID_declarante = '"+rows[j].declarante_ID+"' ")
                    misBeneficiosN[j]=(typeof queryMisBeneficiosN !== 'undefined' && queryMisBeneficiosN)?queryMisBeneficiosN:{}
                
                    for(let k in misBeneficiosN[j]){
                        var queryMisBeneficiosBeneficiariosN = await getResult("select clave,valor from beneficioprivadobeneficiario_n where ID_declarante = '"+rows[j].declarante_ID+"' and ID_beneficioPrivado = '"+misBeneficiosN[j][k].ID_beneficioPrivado+"'")
                        misBeneficiosBeneficiariosN[j]=(typeof queryMisBeneficiosBeneficiariosN !== 'undefined' && queryMisBeneficiosBeneficiariosN)?queryMisBeneficiosBeneficiariosN:{}
                    }
                }
                                                     
//INICIO Ordenamiento de beneficiosPrivados

                misBeneficios=[]
                misBeneficiosAux=[]
                    
                for(let x in misBeneficiosN){
                    for(let y in misBeneficiosN[x]){
                        misBeneficios.push({
                            tipoOperacion:misBeneficiosN[x][y].operacion,
                            tipoPersona:misBeneficiosN[x][y].tipoPersona,
                            tipoBeneficio:{
                                clave:misBeneficiosN[x][y].tipoBeneficioClave,
                                valor:misBeneficiosN[x][y].tipoBeneficioValor
                            },
                            beneficiario:misBeneficiosBeneficiariosN[x],
                            otorgante:{
                                tipoPersona:misBeneficiosN[x][y].otorganteTipoPersona,
                                nombreRazonSocial:misBeneficiosN[x][y].otorganteNombreRazonSocial,
                                rfc:misBeneficiosN[x][y].otorganteRFC,
                            },
                            formaRecepcion:misBeneficiosN[x][y].formaRecepcion,
                            especifiqueBeneficio:misBeneficiosN[x][y].especifiqueBeneficiario,
                            montoMensualAproximado:{
                                valor:misBeneficiosN[x][y].montoMensualAproxValor,
                                moneda:misBeneficiosN[x][y].montoMensualAproxMoneda
                            },
                            sector:{
                                clave:misBeneficiosN[x][y].sectorClave,
                                valor:misBeneficiosN[x][y].sectorValor
                            }
                        })
                    }
                    misBeneficiosAux[x]=misBeneficios
                    misBeneficios=[]
                }

//FIN Ordenamiento de beneficiosPrivados

                misFideicomisosN=[]

                for(let j in rows){
                    var queryMisFideicomisosN = await getResult("select * from fideicomisos_n where ID_declarante = '"+rows[j].declarante_ID+"' ")
                    misFideicomisosN[j]=(typeof queryMisFideicomisosN !== 'undefined' && queryMisFideicomisosN)?queryMisFideicomisosN:{}
                }
                                                     
//INICIO Ordenamiento de fideicomisos

                misFideicomisos=[]
                misFideicomisosAux=[]
                    
                for(let x in misFideicomisosN){
                    for(let y in misFideicomisosN[x]){
                        misFideicomisos.push({
                            tipoOperacion:misFideicomisosN[x][y].operacion,
                            tipoRelacion:misFideicomisosN[x][y].tipoRelacion,
                            tipoFideicomiso:misFideicomisosN[x][y].tipoFideicomiso,
                            tipoParticipacion:misFideicomisosN[x][y].tipoParticipacion,
                            rfcFideicomiso:misFideicomisosN[x][y].rfcFideicomiso,
                            fideicomitente:{
                                tipoPersona:misFideicomisosN[x][y].tipoPersona,
                                nombreRazonSocial:misFideicomisosN[x][y].nombreRazonSocial,
                                rfc:misFideicomisosN[x][y].rfc
                            },
                            fiduciario:{
                                nombreRazonSocial:misFideicomisosN[x][y].nombreFiduciarioRazonSocial,
                                rfc:misFideicomisosN[x][y].rfcFiduciario,
                            },
                            fideicomisario:{
                                tipoPersona:misFideicomisosN[x][y].fideicomisarioTipoPersona,
                                nombreRazonSocial:misFideicomisosN[x][y].fideicomisarioRazonSocial,
                                rfc:misFideicomisosN[x][y].rfcFideicomisario
                            },
                            sector:{
                                clave:misFideicomisosN[x][y].sectorClave,
                                valor:misFideicomisosN[x][y].sectorValor
                            },
                            extranjero:misFideicomisosN[x][y].extranjero
                        })
                    }
                    misFideicomisosAux[x]=misFideicomisos
                    misFideicomisos=[]
                }

//FIN Ordenamiento de fideicomisos

            } catch (error) {
                return res.status(400).send({code: 'SQL ERROR', message: 'Error en segmento de subconsultas'});
            }

//----------------------------------------------------------------------------------------------------------------------------------------------------

//------------------------------------------ F O R M A T O  P A R A  R E S U L T A D O --------------------------------------------------------------------

//------------------------------------------------------------------------------------------------------------------------------------------------------

        var jsonAux=[]
        var jsonFormatter={}

        /*    
        for(let aux in rows){
        console.log("ides: "+rows[aux].declarante_ID)
        console.log("mis date en datos pareja: "+rows[aux].fechaNacmientoPareja==null?"true":"false")
        console.log("Fechas: "+rows[aux].fechaDeclaracion)}
        */

        for(let aux in rows){
            jsonFormatter={}
            
            jsonFormatter={            
                    
                id:rows[aux].declarante_ID+"",
                metadata:{
                    actualizacion:formatFechaTiempo(rows[aux].fechaDeclaracion),
                    institucion:rows[aux].institucion,
                    tipo:rows[aux].tipoDeclaracion,
                    declaracionCompleta:(rows[aux].completa)?true:false,
                    actualizacionConflictoInteres:(rows[aux].conflictoInteres)?true:false
                },
                declaracion:{
                    situacionPatrimonial:{
                        datosGenerales:{
                            nombre:rows[aux].nombre,
                            primerApellido:rows[aux].primerApellido,
                            segundoApellido:rows[aux].segundoApellido,
                            curp:rows[aux].curp,
                            rfc:{
                                rfc:rows[aux].rfc,
                                homoClave:rows[aux].homoClave
                            },
                            correoElectronico:{
                                institucional:rows[aux].correoInstitucional,
                                personal:rows[aux].correoElectronico
                            },
                            telefono:{
                                casa:rows[aux].numeroCasa,
                                celularPersonal:rows[aux].celularPersonal
                            },
                            situacionPersonalEstadoCivil:{
                                clave:rows[aux].estadoCivilClave,
                                valor:rows[aux].estadoCivilValor
                            },
                            regimenMatrimonial:{
                                clave:rows[aux].regimenMatrimonialClave,
                                valor:rows[aux].regimenMatrimonialValor
                            },
                            paisNacimiento:rows[aux].paisNacimiento,
                            nacionalidad:rows[aux].nacionalidad,
                            aclaracionesObservaciones:rows[aux].aclaracionesObservaciones
                        },
                        domicilioDeclarante:{
                            domicilioMexico:{
                                calle:rows[aux].domicilioMexico,
                                numeroExterior:rows[aux].numeroExterior,
                                numeroInterior:rows[aux].numeroInterior,
                                coloniaLocalidad:rows[aux].coloniaLocalidad,
                                municipioAlcaldia:{
                                    clave:rows[aux].municipioAlcaldiaClave,
                                    valor:rows[aux].municipioAlcaldiaValor
                                },
                                entidadFederativa:{
                                    clave:rows[aux].claveEntidadFederativa,
                                    valor:rows[aux].valorEntidadFederativa
                                },
                                codigoPostal:rows[aux].codigoPostal
                                },
                            domicilioExtranjero:{
                                calle:rows[aux].calleExtranjero,
                                numeroExterior:rows[aux].numeroExteriorExtranjero,
                                numeroInterior:rows[aux].numeroInteriorExtranjero,
                                coloniaLocalidad:rows[aux].ciudadLocalidadExtranjero,
                                estadoProvincia:rows[aux].estadoProvinciaExtranjero,
                                pais:rows[aux].paisExtranjero,
                                codigoPostal:rows[aux].codigoPostalExtranjero
                            },
                            aclaracionesObservaciones:rows[aux].aclaracionesObservacionesDomicilio
                        },
                        datosCurricularesDeclarante:{
                            escolaridad:misEscolaridadesAux[aux],
                            aclaracionesObservaciones:rows[aux].aclaracionesObservacionesDatosCur,
                        },
                        datosEmpleoCargoComision:(rows[aux].tipoDeclaracion.toUpperCase().charAt(0)==M)?({
                            tipoOperacion:rows[aux].operacionEmpleoCargoComision,
                            nivelOrdenGobierno:rows[aux].nivelOrdenGobierno,
                            ambitoPublico:rows[aux].ambitoPublico,
                            nombreEntePublico:rows[aux].nombreEntePublico,
                            areaAdscripcion:rows[aux].areaAdscripcion,
                            empleoCargoComision:rows[aux].empleoCargoComision,
                            contratadoPorHonorarios:(rows[aux].contratadoPorHonorarios)?true:false,
                            nivelEmpleoCargoComision:rows[aux].nivelEmpleoCargoComision,
                            funcionPrincipal:rows[aux].funcionPrincipal,
                            fechaTomaPosesion:formatFecha(rows[aux].fechaTomaPosesion),
                            telefonoOficina:{
                                telefono:rows[aux].telefonoOficina,
                                extension:rows[aux].extensionOficina
                            },
                            domicilioMexico:{
                                calle:rows[aux].calleOficina,
                                numeroExterior:rows[aux].numeroExteriorDatosEmpleo,
                                numeroInterior:rows[aux].numeroInteriorDatosEmpleo,
                                coloniaLocalidad:rows[aux].coloniaLocalidadDatosEmpleo,
                                municipioAlcaldia:{
                                    clave:rows[aux].municipioAlcaldiaClaveDatosEmpleo,
                                    valor:rows[aux].municipioAlcaldiaValorDatosEmpleo
                                },
                                entidadFederativa:{
                                    clave:rows[aux].entidadFederativaClaveDatosEmpleo,
                                    valor:rows[aux].entidadFederativaValorDatosEmpleo
                                },
                                codigoPostal:rows[aux].codigoPostalDatosEmpleo
                            },
                            domicilioExtranjero:{
                                calle:rows[aux].calleOficinaExtranjero,
                                numeroExterior:rows[aux].numeroExteriorExtranjeroDatosEmpleo,
                                numeroInterior:rows[aux].numeroInteriorExtranjeroDatosEmpleo,
                                coloniaLocalidad:rows[aux].ciudadLocalidadExtranjeroDatosEmpleo,
                                estadoProvincia:rows[aux].estadoProvinciaExtranjeroDatosEmpleo,
                                pais:rows[aux].paisDatosEmpleo,
                                codigoPostal:rows[aux].codigoPostalExtranjeroDatosEmpleo
                            },
                            aclaracionesObservaciones:rows[aux].aclaracionesObersvacionesDatosEmpleo,
                            cuentaConOtroCargoPublico:(rows[aux].cuentaConOtroCargoPublico)?true:false,
                            otroEmpleoCargoComision:misOtrosEmpleosAux[aux]
                        }
                        ):({
                            tipoOperacion:rows[aux].operacionEmpleoCargoComision,
                            nivelOrdenGobierno:rows[aux].nivelOrdenGobierno,
                            ambitoPublico:rows[aux].ambitoPublico,
                            nombreEntePublico:rows[aux].nombreEntePublico,
                            areaAdscripcion:rows[aux].areaAdscripcion,
                            empleoCargoComision:rows[aux].empleoCargoComision,
                            contratadoPorHonorarios:(rows[aux].contratadoPorHonorarios)?true:false,
                            nivelEmpleoCargoComision:rows[aux].nivelEmpleoCargoComision,
                            funcionPrincipal:rows[aux].funcionPrincipal,
                            fechaTomaPosesion:formatFecha(rows[aux].fechaTomaPosesion),
                            telefonoOficina:{
                                telefono:rows[aux].telefonoOficina,
                                extension:rows[aux].extensionOficina
                            },
                            domicilioMexico:{
                                calle:rows[aux].calleOficina,
                                numeroExterior:rows[aux].numeroExteriorDatosEmpleo,
                                numeroInterior:rows[aux].numeroInteriorDatosEmpleo,
                                coloniaLocalidad:rows[aux].coloniaLocalidadDatosEmpleo,
                                municipioAlcaldia:{
                                    clave:rows[aux].municipioAlcaldiaClaveDatosEmpleo,
                                    valor:rows[aux].municipioAlcaldiaValorDatosEmpleo
                                },
                                entidadFederativa:{
                                    clave:rows[aux].entidadFederativaClaveDatosEmpleo,
                                    valor:rows[aux].entidadFederativaValorDatosEmpleo
                                },
                                codigoPostal:rows[aux].codigoPostalDatosEmpleo
                            },
                            domicilioExtranjero:{
                                calle:rows[aux].calleOficinaExtranjero,
                                numeroExterior:rows[aux].numeroExteriorExtranjeroDatosEmpleo,
                                numeroInterior:rows[aux].numeroInteriorExtranjeroDatosEmpleo,
                                coloniaLocalidad:rows[aux].ciudadLocalidadExtranjeroDatosEmpleo,
                                estadoProvincia:rows[aux].estadoProvinciaExtranjeroDatosEmpleo,
                                pais:rows[aux].paisDatosEmpleo,
                                codigoPostal:rows[aux].codigoPostalExtranjeroDatosEmpleo
                            },
                            aclaracionesObservaciones:rows[aux].aclaracionesObersvacionesDatosEmpleo
                        }),
                        experienciaLaboral:{
                            ninguno:(rows[aux].ningunoExpLaboral)?true:false,
                            experiencia:[...misExperienciasPublicasAux[aux],...misExperienciasPrivadasAux[aux]],
                            aclaracionesObservaciones:rows[aux].aclaracionesObservacionesExpLaboral
                        },
                        datosPareja:{
                            ninguno:(rows[aux].ningunoPareja)?true:false,
                            tipoOperacion:rows[aux].operacionPareja,
                            nombre:rows[aux].nombrePareja,
                            primerApellido:rows[aux].primerApellidoPareja,
                            segundoApellido:rows[aux].segundoApellidoPareja,
                            fechaNacimiento:formatFecha(rows[aux].fechaNacmientoPareja),
                            rfc:rows[aux].rfcPareja,
                            relacionConDeclarante:rows[aux].relacionConDeclarantePareja,
                            ciudadanoExtranjero:(rows[aux].ciudadanoExtranjeroPareja)?true:false,
                            curp:rows[aux].curpPareja,
                            esDependienteEconomico:(rows[aux].esDependienteEconomicoPareja)?true:false,
                            habitaDomicilioDeclarante:(rows[aux].habitaDomicilioDeclarantePareja)?true:false,
                            lugarDondeReside:rows[aux].lugarDondeResidePareja,
                            domicilioMexico:{
                                calle:rows[aux].domicilioMexicoCallePareja,
                                numeroExterior:rows[aux].numeroMexicoExteriorPareja,
                                numeroInterior:rows[aux].numeroMexicoInteriorPareja,
                                coloniaLocalidad:rows[aux].coloniaMexicoLocalidadPareja,
                                municipioAlcaldia:{
                                    clave:rows[aux].municipioMexicoClavePareja,
                                    valor:rows[aux].municipioMexicoValorPareja
                                },
                                entidadFederativa:{
                                    clave:rows[aux].entidadFederativaClavePareja,
                                    valor:rows[aux].entidadFedarativaValorPareja
                                },
                                codigoPostal:rows[aux].codigoMexicoPostalPareja
                            },
                            domicilioExtranjero:{
                                calle:rows[aux].calleExtranjeroPareja,
                                numeroExterior:rows[aux].numeroExtranjeroExteriorPareja,
                                numeroInterior:rows[aux].numeroExtranjeroInteriorPareja,
                                coloniaLocalidad:rows[aux].ciudadExtranjeroLocalidadPareja,
                                estadoProvincia:rows[aux].estadoExtranjeroProvinciaPareja,
                                pais:rows[aux].paisExtranjeroPareja,
                                codigoPostal:rows[aux].codigoExtranjeroPostalPareja
                            },
                            actividadLaboral:{
                                clave:rows[aux].actividadLaboralClavePareja,
                                valor:rows[aux].actividadLaboralValorPareja
                            },
                            actividadLaboralSectorPublico:{
                                nivelOrdenGobierno:rows[aux].nivelOrdenGobiernoPareja,
                                ambitoPublico:rows[aux].ambitoPublicoPareja,
                                nombreEntePublico:rows[aux].nombreEntePublicoPareja,
                                areaAdscripcion:rows[aux].areaAdscripcionPareja,
                                empleoCargoComision:rows[aux].empleoCargoComisionPareja,
                                funcionPrincipal:rows[aux].funcionPrincipalPareja,
                                salarioMensualNeto:{
                                    valor:rows[aux].salarioMensualNetoValorPareja,
                                    moneda:rows[aux].salarioMensualNetoMonedaPareja
                                },
                                fechaIngreso:formatFecha(rows[aux].fechaIgresoPareja)
                            },
                            actividadLaboralSectorPrivadoOtro:{
                                nombreEmpresaSociedadAsociacion:rows[aux].nombreEmpresaSociedadAsociacionPareja,
                                empleoCargoComision:rows[aux].empleoCargoComision2Pareja,
                                rfc:rows[aux].rfc2Pareja,
                                fechaIngreso:formatFecha(rows[aux].fechaIngresoPrivadoPareja),
                                sector:{
                                    clave:rows[aux].sectorPrivadoClavePareja,
                                    valor:rows[aux].sectorPrivadoValorPareja
                                },
                                salarioMensualNeto:{
                                    valor:rows[aux].salarioMensualNetoPrivadoValorPareja,
                                    moneda:rows[aux].salarioMensualNetoPrivadoMonedaPareja
                                },
                                proveedorContratistaGobierno:(rows[aux].proveedorContratistaGobiernoPareja)?true:false,
                            },
                            aclaracionesObservaciones:rows[aux].aclaracionesObservacionesPareja
                        },
                        datosDependienteEconomico:{
                            ninguno:(rows[aux].ningunoDependiente)?true:false,
                            dependienteEconomico:misDependientesEconomicosAux[aux],
                            aclaracionesObservaciones:rows[aux].aclaracionesObservacionesDependiente

                        },
                        ingresos:(rows[aux].tipoDeclaracion.toUpperCase().charAt(0)==I)?({
                            remuneracionMensualCargoPublico:{
                                valor:rows[aux].remuneracionCargoPublicoValor,
                                moneda:rows[aux].remuneracionCargoPublicoMoneda
                            },
                            otrosIngresosMensualesTotal:{
                                valor:rows[aux].otrosIngresosValor,
                                moneda:rows[aux].otrosIngresosMoneda
                            },
                            actividadIndustialComercialEmpresarial:{
                                remuneracionTotal:{
                                    valor:rows[aux].actividadIndustrialComercialEmpresarialTotalValor,
                                    moneda:rows[aux].actividadIndustrialComercialEmpresarialTotalMoneda
                                },
                                actividades:misIngresosIndustrialesAux[aux]
                            },
                            actividadFinanciera:{
                                remuneracionTotal:{
                                    valor:rows[aux].actividadFinancieraTotalValor,
                                    moneda:rows[aux].actividadFinancieraTotalMoneda
                                },
                                actividades:misIngresosFinancierosAux[aux]
                            },
                            serviciosProfesionales:{
                                remuneracionTotal:{
                                    valor:rows[aux].serviciosProfesionalesTotalValor,
                                    moneda:rows[aux].serviciosProfesionalesTotalMoneda
                                },
                                servicios:misIngresosProfesionalesAux[aux]
                            },
                            otrosIngresos:{
                                remuneracionTotal:{
                                    valor:rows[aux].otrosIngresosTotalValor,
                                    moneda:rows[aux].otrosIngresosTotalMoneda
                                },
                                ingresos:misIngresosOtrosAux[aux]
                            },
                            ingresoMensualNetoDeclarante:{
                                valor:rows[aux].ingresoNetoDeclaranteValor,
                                moneda:rows[aux].ingresoNetoDeclaranteMoneda
                            },
                            ingresoMensualNetoParejaDependiente:{
                                valor:rows[aux].ingresoNetoParejaDependienteValor,
                                moneda:rows[aux].ingresoNetoParejaDependienteMoneda
                            },
                            totalIngresosMensualesNetos:{
                                valor:rows[aux].totalIngresosNetosValor,
                                moneda:rows[aux].totalIngresosNetosMoneda
                            },
                            aclaracionesObservaciones:rows[aux].aclaracionesObservacionesIngresos
                        
                        }):(rows[aux].tipoDeclaracion.toUpperCase().charAt(0)==M)?({
                            
                            remuneracionAnualCargoPublico:{
                                valor:rows[aux].remuneracionCargoPublicoValor,
                                moneda:rows[aux].remuneracionCargoPublicoMoneda
                            },
                            otrosIngresosAnualesTotal:{
                                valor:rows[aux].otrosIngresosValor,
                                moneda:rows[aux].otrosIngresosMoneda
                            },
                            actividadIndustialComercialEmpresarial:{
                                remuneracionTotal:{
                                    valor:rows[aux].actividadIndustrialComercialEmpresarialTotalValor,
                                    moneda:rows[aux].actividadIndustrialComercialEmpresarialTotalMoneda
                                },
                                actividades:misIngresosIndustrialesAux[aux]
                            },
                            actividadFinanciera:{
                                remuneracionTotal:{
                                    valor:rows[aux].actividadFinancieraTotalValor,
                                    moneda:rows[aux].actividadFinancieraTotalMoneda
                                },
                                actividades:misIngresosFinancierosAux[aux]
                            },
                            serviciosProfesionales:{
                                remuneracionTotal:{
                                    valor:rows[aux].serviciosProfesionalesTotalValor,
                                    moneda:rows[aux].serviciosProfesionalesTotalMoneda
                                },
                                servicios:misIngresosProfesionalesAux[aux]
                            },
                            enajenacionBienes:{
                                remuneracionTotal:{
                                    valor:rows[aux].enajenacionBienesTotalValor,
                                    moneda:rows[aux].enajenacionBienesTotalMoneda
                                },
                                bienes:misIngresosEnajenacionesAux[aux]
                            },
                            otrosIngresos:{
                                remuneracionTotal:{
                                    valor:rows[aux].otrosIngresosTotalValor,
                                    moneda:rows[aux].otrosIngresosTotalMoneda
                                },
                                ingresos:misIngresosOtrosAux[aux]
                            },
                            ingresoAnualNetoDeclarante:{
                                valor:rows[aux].ingresoNetoDeclaranteValor,
                                moneda:rows[aux].ingresoNetoDeclaranteMoneda
                            },
                            ingresoAnualNetoParejaDependiente:{
                                valor:rows[aux].ingresoNetoParejaDependienteValor,
                                moneda:rows[aux].ingresoNetoParejaDependienteMoneda
                            },
                            totalIngresosAnualesNetos:{
                                valor:rows[aux].totalIngresosNetosValor,
                                moneda:rows[aux].totalIngresosNetosMoneda
                            },
                            aclaracionesObservaciones:rows[aux].aclaracionesObservacionesIngresos
                        
                        }):({
                            
                            remuneracionConclusionCargoPublico:{
                                valor:rows[aux].remuneracionCargoPublicoValor,
                                moneda:rows[aux].remuneracionCargoPublicoMoneda
                            },
                            otrosIngresosConclusionTotal:{
                                valor:rows[aux].otrosIngresosValor,
                                moneda:rows[aux].otrosIngresosMoneda
                            },
                            actividadIndustialComercialEmpresarial:{
                                remuneracionTotal:{
                                    valor:rows[aux].actividadIndustrialComercialEmpresarialTotalValor,
                                    moneda:rows[aux].actividadIndustrialComercialEmpresarialTotalMoneda
                                },
                                actividades:misIngresosIndustrialesAux[aux]
                            },
                            actividadFinanciera:{
                                remuneracionTotal:{
                                    valor:rows[aux].actividadFinancieraTotalValor,
                                    moneda:rows[aux].actividadFinancieraTotalMoneda
                                },
                                actividades:misIngresosFinancierosAux[aux]
                            },
                            serviciosProfesionales:{
                                remuneracionTotal:{
                                    valor:rows[aux].serviciosProfesionalesTotalValor,
                                    moneda:rows[aux].serviciosProfesionalesTotalMoneda
                                },
                                servicios:misIngresosProfesionalesAux[aux]
                            },
                            enajenacionBienes:{
                                remuneracionTotal:{
                                    valor:rows[aux].enajenacionBienesTotalValor,
                                    moneda:rows[aux].enajenacionBienesTotalMoneda
                                },
                                bienes:misIngresosEnajenacionesAux[aux]
                            },
                            otrosIngresos:{
                                remuneracionTotal:{
                                    valor:rows[aux].otrosIngresosTotalValor,
                                    moneda:rows[aux].otrosIngresosTotalMoneda
                                },
                                ingresos:misIngresosOtrosAux[aux]
                            },
                            ingresoConclusionNetoDeclarante:{
                                valor:rows[aux].ingresoNetoDeclaranteValor,
                                moneda:rows[aux].ingresoNetoDeclaranteMoneda
                            },
                            ingresoConclusionNetoParejaDependiente:{
                                valor:rows[aux].ingresoNetoParejaDependienteValor,
                                moneda:rows[aux].ingresoNetoParejaDependienteMoneda
                            },
                            totalIngresosConclusionNetos:{
                                valor:rows[aux].totalIngresosNetosValor,
                                moneda:rows[aux].totalIngresosNetosMoneda
                            },
                            aclaracionesObservaciones:rows[aux].aclaracionesObservacionesIngresos
                        
                        }),
                        actividadAnualAnterior:(rows[aux].tipoDeclaracion.toUpperCase().charAt(0)!=M)?({
                            servidorPublicoAnioAnterior:(rows[aux].servidorPublicoAA)?true:false,
                            fechaIngreso:formatFecha(rows[aux].fechaIngresoAA),
                            fechaConclusion:formatFecha(rows[aux].fechConclusionAA),
                            remuneracionNetaCargoPublico:{
                                valor:rows[aux].remuneracionNetaCargoPublicoValorAA,
                                moneda:rows[aux].remuneracionNetaCargoPublicoMonedaAA
                            },
                            otrosIngresosTotal:{
                                valor:rows[aux].otrosIngresosValorAA,
                                moneda:rows[aux].otrosIngresosMonedaAA
                            },
                            actividadIndustialComercialEmpresarial:{
                                remuneracionTotal:{
                                    valor:rows[aux].actividadIndustrialComercialEmpresarialTotalValorAA,
                                    moneda:rows[aux].actividadIndustrialComercialEmpresarialTotalMonedaAA
                                },
                                actividades:misIngresosIndustrialesAnioAntAux[aux]
                            },
                            actividadFinanciera:{
                                remuneracionTotal:{
                                    valor:rows[aux].actividadFinancieraTotalValorAA,
                                    moneda:rows[aux].actividadFinancieraTotalMonedaAA
                                },
                                actividades:misIngresosFinancierosAnioAntAux[aux]
                            },
                            serviciosProfesionales:{
                                remuneracionTotal:{
                                    valor:rows[aux].serviciosProfesionalesTotalValorAA,
                                    moneda:rows[aux].serviciosProfesionalesTotalMonedaAA
                                },
                                servicios:misIngresosProfesionalesAnioAntAux[aux]
                            },
                            enajenacionBienes:{
                                remuneracionTotal:{
                                    valor:rows[aux].enajenacionBienesTotalValorAA,
                                    moneda:rows[aux].enajenacionBienesTotalMonedaAA
                                },
                                bienes:misIngresosEnajenacionesAnioAntAux[aux]
                            },
                            otrosIngresos:{
                                remuneracionTotal:{
                                    valor:rows[aux].otrosIngresosTotalValorAA,
                                    moneda:rows[aux].otrosIngresosTotalMonedaAA
                                },
                                ingresos:misIngresosOtrosAnioAntAux[aux]
                            },
                            ingresoNetoAnualDeclarante:{
                                valor:rows[aux].ingresoNetoDeclaranteValorAA,
                                moneda:rows[aux].ingresoNetoDeclaranteMonedaAA
                            },
                            ingresoNetoAnualParejaDependiente:{
                                valor:rows[aux].ingresoNetoParejaDependienteValorAA,
                                moneda:rows[aux].ingresoNetoParejaDependienteMonedaAA
                            },
                            totalIngresosNetosAnuales:{
                                valor:rows[aux].totalIngresosNetosValorAA,
                                moneda:rows[aux].totalIngresosNetosMonedaAA
                            },
                            aclaracionesObservaciones:rows[aux].aclaracionesObservacionesAA
                        }):null,
                        bienesInmuebles:{
                            ninguno:(rows[aux].ningunoBienInmueble)?true:false,
                            bienInmueble:misBienesInmueblesAux[aux],
                            aclaracionesObservaciones:rows[aux].aclaracionesObservacionesBienInmueble
                        },
                        vehiculos:{
                            ninguno:(rows[aux].ningunoVehiculo)?true:false,
                            vehiculo:misVehiculosAux[aux],
                            aclaracionesObservaciones:rows[aux].aclaracionesObservacionesVehiculo
                        },
                        bienesMuebles:{
                            ninguno:(rows[aux].ningunoBienMueble)?true:false,
                            bienMueble:misBienesMueblesAux[aux],
                            aclaracionesObservaciones:rows[aux].aclaracionesObservacionesBienMueble
                        },
                        inversiones:{
                            ninguno:(rows[aux].ningunoInversion)?true:false,
                            inversion:misInversionesAux[aux],
                            aclaracionesObservaciones:rows[aux].aclaracionesObservacionesInversion
                        },
                        adeudos:{
                            ninguno:(rows[aux].ningunoAdeudo)?true:false,
                            adeudo:misAdeudosAux[aux],
                            aclaracionesObservaciones:rows[aux].aclaracionesObservacionesAdeudo
                        },
                        prestamoComodato:{
                            ninguno:(rows[aux].ningunoPrestamo)?true:false,
                            prestamo:misPrestamosAux[aux],
                            aclaracionesObservaciones:rows[aux].aclaracionesObservacionesPrestamo
                        }
                    },
                    interes:{
                        participacion:{
                            ninguno:(rows[aux].ningunoParticipacion)?true:false,
                            participacion:misParticipacionesAux[aux],
                            aclaracionesObservaciones:rows[aux].aclaracionesObservacionesParticipacion
                        },
                        participacionTomaDecisiones:{
                            ninguno:(rows[aux].ningunoTomaDecision)?true:false,
                            participacion:misTomaDecisionesAux[aux],
                            aclaracionesObservaciones:rows[aux].aclaracionesObservacionesTomaDecision
                        },
                        apoyos:{
                            ninguno:(rows[aux].ningunoApoyo)?true:false,
                            apoyo:misApoyosAux[aux],
                            aclaracionesObservaciones:rows[aux].aclaracionesObservacionesApoyo
                        },
                        representacion:{
                            ninguno:(rows[aux].ningunoRepresentacion)?true:false,
                            representacion:misRepresentacionesAux[aux],
                            aclaracionesObservaciones:rows[aux].aclaracionesObservacionesRepresentacion
                        },
                        clientesPrincipales:{
                            ninguno:(rows[aux].ningunoCliente)?true:false,
                            cliente:misClientesAux[aux],
                            aclaracionesObservaciones:rows[aux].aclaracionesObservacionesCliente
                        },
                        beneficiosPrivados:{
                            ninguno:(rows[aux].ningunoBeneficio)?true:false,
                            beneficio:misBeneficiosAux[aux],
                            aclaracionesObservaciones:rows[aux].aclaracionesObservacionesBeneficio
                        },
                        fideicomisos:{
                            ninguno:(rows[aux].ningunoFideicomiso)?true:false,
                            fideicomiso:misFideicomisosAux[aux],
                            aclaracionesObservaciones:rows[aux].aclaracionesObservacionesFideicomiso
                        }
                    }
                }
            }

            if(rows[aux].tipoDeclaracion.toUpperCase().charAt(0)==M)
            delete jsonFormatter.declaracion.situacionPatrimonial.actividadAnualAnterior

            jsonChingon = removerNulos(jsonFormatter)
            //jsonChingon = jsonFormatter
            removerVacios(jsonChingon)
            jsonAux.push(jsonChingon)
                            
        }

//-----------------------------------------------------------------------------------------------------------------------

        //Se divide el resultado de la consulta en base a la paginación
        var resultJson=jsonAux.slice(indexInicio,indexFin);
        
        //Número de páginas
        const pageCalculado=Math.ceil(jsonAux.length/limit);
        
        resultJson=(page<1||page>pageCalculado)?[]:resultJson;//Manda [] si la página es inválida o no existe
        
        //Control de parámetros para hasPreviousPage y hasNextPage
        nextPage=(page>=pageCalculado||page<0)?false:true;
        prevPage=(page>pageCalculado+1||page<2)?false:true;

        //Construcción del JSON a consumir
        const pagination = 
        {
        hasNextPage : nextPage, //¿Existe una página despues de la actual?
        hasPreviousPage : prevPage, //¿Existe una página antes de la actual?
        pageSize : parseInt(limit), //numero de elementos en cada página
        page : parseInt(page), //página actual
        totalPages : pageCalculado, //total de páginas
        totalRows : rows.length //total de elementos
        }

        const autorizacion = 
        {
            token : authData.tokenAuth,
            iat : new Date(authData.iat*1000).toString(),
            exp : new Date(authData.exp*1000).toString()
        }

        res.status(200).json({
            autorizacion, //Datos de autorización (usuario,password,tiempo de emisión de sesión,tiempo de expiración de sesión)
            pagination, //Datos de páginación
            results: resultJson //Consulta
            // resultado: jsonAux
        });

    }else{
        return res.status(400).send({code: 'SQL ERROR', message: 'ERROR EN CONSULTA !!! -> '+err});
    }
        
    });// Fin del espacio de consultas a base de datos             
    }//Fin ELSE (autorizacion)
}); //Fin de la función de verificar token
}); //Fin del router

//------------------------------------------ F U N C I O N E S --------------------------------------------------------------------

function verificarToken(req,res,next){
    //Obtener Auth Basic del Header
    const bearerHeader = req.headers['authorization'];
    //Verificar si barear está definido
    if(typeof bearerHeader !== 'undefined'){
        const bearer = bearerHeader.split(' ');
        const bearerToken = bearer[1];
        req.token=bearerToken;
        next(); //nos pasamos al siguiente middleware
    }else{
    //No autorizado
    res.status(401).send({
        code: 'No Authorized',
        message: 'No se cuenta con autorización'
    });
    }
}

function prepararQuery(x,w){ //Funcion para traducir el body.query a lenguaje SQL (where clause)
    var preparedQuery=""
    for(let aux in x){       
        preparedQuery=(aux==0)?preparedQuery+" AND "+
        ((x[aux].includes(".min"))?x[aux].replace(".min","")+
        ">="+((Number.isNaN(Number(w[aux])))?0:Number(w[aux]))+"":(x[aux].includes(".max"))?x[aux].replace(".max","")+"<="+
        ((Number.isNaN(Number(w[aux])))?999999999:Number(w[aux]))+"":(x[aux].includes(".ID_declarante"))?x[aux]+" LIKE '%"+w[aux]+"%'":(x[aux].includes("entidadFederativa"))?"(datosempleocargocomision.entidadFederativaClaveDatosEmpleo LIKE '%"+w[aux]+"%' OR datosempleocargocomision.entidadFederativaValorDatosEmpleo LIKE '%"+w[aux]+"%')":(x[aux].includes("municipioAlcaldia"))?"(datosempleocargocomision.municipioAlcaldiaClaveDatosEmpleo LIKE '%"+w[aux]+"%' OR datosempleocargocomision.municipioAlcaldiaValorDatosEmpleo LIKE '%"+w[aux]+"%')":(x[aux].includes("formaAdquisicion"))?"(bienesinmuebles_n.formaAdquisicionClave LIKE '%"+w[aux]+"%' OR bienesinmuebles_n.formaAdquisicionValor LIKE '%"+w[aux]+"%')":(x[aux].includes("escolaridad"))?"(datoscurricularesdeclarante_n.escolaridadClave LIKE '%"+w[aux]+"%' OR datoscurricularesdeclarante_n.escolaridadValor LIKE '%"+w[aux]+"%')":x[aux]+" LIKE '%"+w[aux]+"%'")+"":preparedQuery+" AND "+
        ((x[aux].includes(".min"))?x[aux].replace(".min","")+
        ">="+((Number.isNaN(Number(w[aux])))?0:Number(w[aux]))+"":(x[aux].includes(".max"))?x[aux].replace(".max","")+"<="+
        ((Number.isNaN(Number(w[aux])))?999999999:Number(w[aux]))+"":(x[aux].includes(".ID_declarante"))?x[aux]+" LIKE '%"+w[aux]+"%'":(x[aux].includes("entidadFederativa"))?"(datosempleocargocomision.entidadFederativaClaveDatosEmpleo LIKE '%"+w[aux]+"%' OR datosempleocargocomision.entidadFederativaValorDatosEmpleo LIKE '%"+w[aux]+"%')":(x[aux].includes("municipioAlcaldia"))?"(datosempleocargocomision.municipioAlcaldiaClaveDatosEmpleo LIKE '%"+w[aux]+"%' OR datosempleocargocomision.municipioAlcaldiaValorDatosEmpleo LIKE '%"+w[aux]+"%')":(x[aux].includes("formaAdquisicion"))?"(bienesinmuebles_n.formaAdquisicionClave LIKE '%"+w[aux]+"%' OR bienesinmuebles_n.formaAdquisicionValor LIKE '%"+w[aux]+"%')":(x[aux].includes("escolaridad"))?"(datoscurricularesdeclarante_n.escolaridadClave LIKE '%"+w[aux]+"%' OR datoscurricularesdeclarante_n.escolaridadValor LIKE '%"+w[aux]+"%')":x[aux]+" LIKE '%"+w[aux]+"%'")+""
    }
    return preparedQuery
}

function prepararSort(x,w){ //Funcion para traducir el body.sort a lenguaje SQL (order by clause)
    var preparedSort=""
    var primerParametro=true
    for(let aux in x){
        if(w[aux].toLowerCase()==="asc" || w[aux].toLowerCase()==="desc"){
        preparedSort=(primerParametro)?preparedSort+" ORDER BY "+x[aux]+" "+w[aux]+"":preparedSort+" , "+x[aux]+" "+w[aux]+""
        primerParametro=false
        }
    }
    return preparedSort
}

function getResult(sql){ //Funcion para crear espacios de conexion a la base de datos
    return new Promise(function(resolve,reject){
      pool.query(sql, function(err, result){
        if(err){
          reject(err)
        }else{
          resolve(result)
        }
      })
    })
}

function removerNulos(obj) {
    if (Array.isArray(obj)) { 
      return obj
          .map(v => (v && typeof v === 'object') ? removerNulos(v) : v)
          .filter(v => !(v === null) );
          // regresa un arreglo tal que sus valores no sean null
    } else { 
      return Object.entries(obj)
          .map(([k, v]) => [k, v && typeof v === 'object' ? removerNulos(v) : v])
          .reduce((a, [k, v]) => ( ( v === null ) && (v!=false && v!=true)  ) ? a : (a[k]=v, a), {});
          //regresa el objeto sin valores nulos y sin objetos vacíos (va acumulando los valores en un nuevo arreglo que cumplan con la condición)
    } 
  }

function removerVacios(obj) {
    for (var k in obj) {
      if (!obj[k] || typeof obj[k] !== 'object') {
        continue // Si no es objeto avanza a la siguiente iteracion
      }
  
      // La propiedad es un objeto
      removerVacios(obj[k]); // <-- Objetos anidados
      if (Object.keys(obj[k]).length === 0) {
          if(Array.isArray(obj[k])){ //Si el arreglo no tiene propiedades lo hace vacío
              obj[k]=[]
      }else{
            delete obj[k]; }// Si el objeto no tiene propiedades lo elimina
      }
    }
}

//------------------------------------------ F O R M A T O S   F E C H A S --------------------------------------------------------------------

Date.prototype.yyyymmdd = function() {

    var mm = (this.getMonth() + 1);
    var dd = this.getDate();
      
    return [this.getFullYear()+'-',
            (mm<10 ? '0' : '') + mm +'-',
            (dd<10 ? '0' : '') + dd
            ].join('');
    
}

function formatFecha(fecha){
    if(fecha){
        if(fecha.toString().includes('0000')){
            return "0000-00-00"
        }else{
            return fecha.yyyymmdd()
        }
    }else{
        return "0000-00-00"
    }
}

function formatFechaTiempo(fecha){
    if(fecha){
        if(fecha.toString().includes('0000')){
            return "0000-00-00T00:00:00Z"
        }else{
            return fecha.yyyymmddhhmmss()
        }
    }else{
        return "0000-00-00T00:00:00Z"
    }
}

Date.prototype.yyyymmddhhmmss = function() {

    var mm = (this.getMonth() + 1); // getMonth() comienza en cero
    var dd = this.getDate();
  
    return [this.getFullYear()+'-',
            (mm<10 ? '0' : '') + mm +'-',
            (dd<10 ? '0' : '') + dd
           ].join('')+'T'+
           [this.getHours(),
            this.getMinutes(),
            this.getSeconds()].join(':')+'Z';
}

module.exports=router; //para utilizar estas rutas en la aplicación