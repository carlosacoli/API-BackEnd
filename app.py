from io import BytesIO
import json
from flask import Flask, request, jsonify, send_file
from datetime import timedelta, datetime
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import between
from sqlalchemy import func
# import re 

from flask_marshmallow import Marshmallow
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import (create_access_token,  get_jwt_identity, jwt_required, JWTManager)
# import os

app = Flask(__name__)
CORS(app, supports_credentials=True, expose_headers=["Content-Disposition"])


# basedir = os.path.abspath(os.path.dirname(__file__))
# app.config['SQLALCHEMY_DATABASE_URI']= 'sqlite:///' + os.path.join(basedir, 'app.sqlite')
app.config['SQLALCHEMY_DATABASE_URI']= 'postgresql://vwwsqhpzlxsgng:fa80f1b03dd1f2b05c0bce48da7e59c0b69078f69c705bb0cca8ada62a90896a@ec2-34-250-252-161.eu-west-1.compute.amazonaws.com:5432/dfcimeit2ohvdi'
db = SQLAlchemy(app)
ma = Marshmallow(app)
bc = Bcrypt(app)


app.config['JWT_TOKEN_LOCATION'] = ["headers", "cookies"]
app.config['JWT_COOKIE_CSRF_PROTECT'] = False
app.config["JWT_COOKIE_SECURE"] = True
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=3)
#app.config['JWT_ACCESS_COOKIE_PATH'] = '/prueba'

# Create Secret KEY
app.config["JWT_SECRET_KEY"] = "D5*F?_1?-d$f*1_Sndjñ2*$dsj"
jwt = JWTManager(app)

############################################## Users #################################################################### 
#Table users and EndPoints
class Usuarios(db.Model):
    id_usuario = db.Column(db.Integer, primary_key=True)
    nombre_usuario = db.Column(db.String(50), nullable=False, unique=False)
    apellidos_usuario = db.Column(db.String(60), nullable=False, unique=False)
    provincia_usuario = db.Column(db.String(30), nullable=False, unique=False)
    ciudad_usuario = db.Column(db.String(30), nullable=False, unique=False)
    direccion_usuario = db.Column(db.VARCHAR(100), nullable=False, unique=False)
    telefono_usuario = db.Column(db.Integer, nullable=False, unique=False)
    fecha_creacion = db.Column(db.Date, nullable=False)
    email_usuario = db.Column(db.VARCHAR(60), nullable=False, unique=True)
    password = db.Column(db.VARCHAR(100), nullable=False, unique=False)
    id_rol_usuario = db.Column(db.Integer, nullable=False, unique=False)

    def __init__(self, nombre_usuario, apellidos_usuario, provincia_usuario, ciudad_usuario, direccion_usuario,  
                 telefono_usuario, fecha_creacion,  email_usuario, password, id_rol_usuario):
        self.nombre_usuario = nombre_usuario
        self.apellidos_usuario = apellidos_usuario
        self.provincia_usuario = provincia_usuario
        self.ciudad_usuario = ciudad_usuario
        self.direccion_usuario = direccion_usuario
        self.telefono_usuario = telefono_usuario
        self.fecha_creacion = fecha_creacion
        self.email_usuario = email_usuario
        self.password = password
        self.id_rol_usuario = id_rol_usuario

class UsuariosSchema(ma.Schema):
    class Meta:
        fields = ('id_usuario','nombre_usuario', 'apellidos_usuario', 'provincia_usuario', 'ciudad_usuario', 
                  'direccion_usuario', 'telefono_usuario', 'fecha_creacion','email_usuario','password', 'id_rol_usuario')
        
usuarios_schema = UsuariosSchema()
multi_usuarios_schema = UsuariosSchema(many=True)


# EndPoint to create a new user
@app.route('/usuario/add', methods=["POST"])
def add_usuario():
    
        nombre_usuario = request.form['nombre']
        apellidos_usuario = request.form['apellidos']
        provincia_usuario = request.form['provincia']
        ciudad_usuario = request.form['ciudad']
        direccion_usuario = request.form['direccion']
        telefono_usuario = request.form['telefono']
        fecha_creacion = request.form['fecha_creacion']
        fecha_creacion = datetime.strptime(fecha_creacion, "%d/%m/%Y")
        email_usuario = request.form['email']
        password = request.form['password']
        id_rol_usuario = request.form['id_rol_usuario']

        pw_hash = bc.generate_password_hash(password, 15).decode('utf-8')
        
        new_usuario = Usuarios(nombre_usuario, apellidos_usuario, provincia_usuario, ciudad_usuario, direccion_usuario, 
                               telefono_usuario, fecha_creacion, email_usuario, pw_hash, id_rol_usuario)
        
        db.session.add(new_usuario)
        db.session.commit()

        return "Usuario creado exitosamente"

        # usuario = Usuarios.query.get(new_usuario.id_usuario)
        # return usuarios_schema.jsonify(usuario)

    
#EndPoint to Verify user
@app.route('/verify', methods=["POST"])
def verify():

    email_usuario = request.json['email_usuario']
    password = request.json['password']

    usuario = db.session.query(Usuarios).filter(Usuarios.email_usuario == email_usuario).first()

    if usuario is None:
        return jsonify({'msg': 'Wrong Email'})
    if not bc.check_password_hash(usuario.password, password):
        return jsonify({'msg': 'Wrong Password'}) 
    access_token = create_access_token(identity={"nombre": usuario.nombre_usuario, "apellidos": usuario.apellidos_usuario , "email": email_usuario, 
                                                 "id_user": usuario.id_usuario , "id_rol": usuario.id_rol_usuario })
    return jsonify({'msg': 'OK', 'token': access_token, "user_id": usuario.id_usuario}), 200
    
    ##in case of cookies
    #set_access_cookies(resp, access_token)
    #return resp, 200

# @app.route("/optionally_protected", methods=["GET"])
# @jwt_required(optional=True)
# def protected():
#     # Access the identity of the current user with get_jwt_identity
#     current_user = get_jwt_identity()
#     if current_user is None:
#         return jsonify({"login_status": False})
#     else:
#         return jsonify({"login_status": True, "logged_in_as": current_user}), 200


# Protect a route with jwt_required, which will kick out requests
# without a valid JWT present.  
@app.route("/protected", methods=["GET"])
@jwt_required(optional=True)
def optionally_protected():
    # Access the identity of the current user with get_jwt_identity
    current_identity = get_jwt_identity()
    return jsonify({"login_status": "ONLINE", "logged_in_as": current_identity}), 200  



#EndPoint to query all users
@app.route('/usuario/get', methods=["GET"])
def get_usuarios():
    all_usuarios = Usuarios.query.all()
    result = multi_usuarios_schema.dump(all_usuarios)
    return jsonify(result), 200

#EndPoint to query all users client
@app.route('/usuario/get/cliente', methods=["GET"])
def get_usuarios_cliente():
    query = db.session.execute(db.select(Usuarios.id_usuario,Usuarios.nombre_usuario, Usuarios.apellidos_usuario, 
                                         Usuarios.email_usuario).where(Usuarios.id_rol_usuario == 3))

    result = multi_usuarios_schema.dump(query)
    return jsonify(result),200


#EndPoint for querying a single user
@app.route('/usuario/get/<id>', methods=["GET"])
def get_single_usuario(id):
    single_usuario = Usuarios.query.get(id)
    return usuarios_schema.jsonify(single_usuario), 200

#EndPoint to query all to edit user
@app.route('/usuario/get_edit/<id>', methods=["GET"])
def get_toedit_user(id):
    query = db.session.execute(db.select(Usuarios.id_usuario,Usuarios.nombre_usuario, Usuarios.apellidos_usuario,Usuarios.provincia_usuario, 
                                         Usuarios.ciudad_usuario, Usuarios.direccion_usuario, Usuarios.telefono_usuario, Usuarios.email_usuario
                                         ).where(Usuarios.id_usuario == id))

    result = multi_usuarios_schema.dump(query)
    return jsonify(result),200

#EndPoint to query all to view user
@app.route('/usuario/get_view/<id>', methods=["GET"])
def get_toview_user(id):
    query = db.session.execute(db.select(Usuarios.id_usuario,Usuarios.nombre_usuario, Usuarios.apellidos_usuario,Usuarios.provincia_usuario, 
                                         Usuarios.ciudad_usuario, Usuarios.direccion_usuario, Usuarios.telefono_usuario, Usuarios.fecha_creacion, 
                                         Usuarios.email_usuario, Usuarios.id_rol_usuario).where(Usuarios.id_usuario == id))

    result = multi_usuarios_schema.dump(query)
    return jsonify(result),200


#EndPoint for updating a user
@app.route('/usuario/update/<id>', methods=["PATCH"])
def usuario_update(id):
    usuario = db.session.get(Usuarios, id)
    nombre_usuario = request.form['nombre']
    apellidos_usuario = request.form['apellidos']
    provincia_usuario = request.form['provincia']
    ciudad_usuario = request.form['ciudad']
    direccion_usuario = request.form['direccion']
    telefono_usuario = request.form['telefono']
    email_usuario = request.form['email']


    usuario.nombre_usuario = nombre_usuario
    usuario.apellidos_usuario = apellidos_usuario
    usuario.provincia_usuario = provincia_usuario
    usuario.ciudad_usuario = ciudad_usuario
    usuario.direccion_usuario = direccion_usuario
    usuario.telefono_usuario = telefono_usuario
    usuario.email_usuario = email_usuario

    db.session.commit()
    return "Usuario actualizado exitosamente"

#EndPoint for updating a user
@app.route('/usuario/update_password/<id>', methods=["PATCH"])
def usuario_update_password(id):
    usuario = db.session.get(Usuarios, id)
    password = request.form['password']

    pw_hash = bc.generate_password_hash(password, 15).decode('utf-8')

    usuario.password = pw_hash
    db.session.commit()
    return "Password Cambiado exitosamente"

#EndPoint for deleting a user
@app.route('/usuario/delete/<id>', methods=["DELETE"])
def usuario_delete(id):
    usuario = Usuarios.query.get(id)
    db.session.delete(usuario)
    db.session.commit()

    return ("El usuario se ha eliminado correctamente!"), 200


################################################ ROL USERS #################################################################### 

#Table rol_usuario and EndPoints
class Rol_usuario(db.Model):
    id_rol = db.Column(db.Integer, primary_key=True)
    nombre_rol = db.Column(db.String(20), nullable=False, unique=False)

    def __init__(self, nombre_rol):
        self.nombre_rol = nombre_rol
        

class Rol_usuarioSchema(ma.Schema):
    class Meta:
        fields = ('id_rol', 'nombre_rol')

rol_schema = Rol_usuarioSchema()
multi_rol_schema = Rol_usuarioSchema(many=True)

# EndPoint to create a new rol for user
@app.route('/rol_usuario/add', methods=["POST"])
def add_rol():
    
    nombre_rol = request.json['nombre_rol']
        
    new_rol = Rol_usuario(nombre_rol)
        
    db.session.add(new_rol)
    db.session.commit()

    rol_creado = Rol_usuario.query.get(new_rol.id_rol)

    return rol_schema.jsonify(rol_creado)


#EndPoint to query all roles
@app.route('/rol_usuario/get', methods=["GET"])
def get_roles():
    all_roles = Rol_usuario.query.all()
    result = multi_rol_schema.dump(all_roles)
    return jsonify(result)


#EndPoint for querying a single rol
@app.route('/rol_usuario/get/<id>', methods=["GET"])
def get_single_rol(id):
     single_rol = Rol_usuario.query.get(id)
     return rol_schema.jsonify(single_rol)


#EndPoint for updating a rol
@app.route('/rol_usuario/update/<id>', methods=["PUT"])
def rol_update(id):
    rol_usuario = Rol_usuario.query.get(id)
    nombre_rol = request.json['nombre_rol']

    rol_usuario.nombre_rol = nombre_rol

    db.session.commit()
    return rol_schema.jsonify(rol_usuario)

#EndPoint for deleting a rol
@app.route('/rol_usuario/delete/<id>', methods=["DELETE"])
def rol_delete(id):
    rol_usuario = Rol_usuario.query.get(id)
    db.session.delete(rol_usuario)
    db.session.commit()

    return "El rol de usuario se ha eliminado correctamente!"

############################################## FACTURAS INGRESOS #################################################################### 
#Table Factura_ingreso and EndPoints
class Factura_ingreso(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    concepto = db.Column(db.String (100), nullable=False)
    fecha_ingreso = db.Column(db.Date, nullable=False)
    fecha_subida = db.Column(db.Date, nullable=False)
    base_imp = db.Column(db.Integer, nullable=False)
    iva = db.Column(db.Integer, nullable=False)
    total_ingreso = db.Column(db.Integer, nullable=False)
    archivo = db.Column(db.LargeBinary, nullable=False)
    nombre_archivo = db.Column(db.VARCHAR(100), nullable=False)
    estado_factura = db.Column(db.String, nullable=False)
    id_factura_usuario = db.Column(db.Integer)

    def __init__(self, concepto, fecha_ingreso, fecha_subida, base_imp, iva, 
                 total_ingreso, archivo, nombre_archivo, estado_factura, id_factura_usuario):
        self.concepto = concepto
        self.fecha_ingreso = fecha_ingreso
        self.fecha_subida = fecha_subida
        self.base_imp = base_imp
        self.iva = iva
        self.total_ingreso = total_ingreso
        self.archivo = archivo
        self.nombre_archivo = nombre_archivo
        self.estado_factura = estado_factura
        self.id_factura_usuario = id_factura_usuario


class Factura_ingresoSchema(ma.Schema):
    class Meta:
        fields = ('id','concepto','fecha_ingreso','fecha_subida','base_imp','iva',
                  'total_ingreso','archivo','nombre_archivo','estado_factura','id_factura_usuario')
        
factura_ingreso_schema = Factura_ingresoSchema()
multi_factura_ingreso_schema = Factura_ingresoSchema(many=True)

# EndPoint to create a new factura_ingreso
@app.route('/factura_ingreso/add', methods=["POST"])
def add_factura_ingreso():

        #METOD MENTOR
        # data = request.get_json()
        # concepto = data.get('concepto')
        # fecha_ingreso = data.get('fecha_ingreso')
        # fecha_subida = data.get('fecha_subida')
        # base_imp = data.get('base_imp')
        # iva = data.get('iva')
        # total_ingreso = data.get('total_ingreso')
        # archivo = data.get('archivo')
        # estado_factura = data.get('estado_factura')
        # id_factura_usuario = data.get('id_factura_usuario')

        # return jsonify(factura_ingreso_schema.dump(new_factura_ingreso)) //METOD MENTOR


        concepto = request.form['concepto']
        fecha_ingreso = request.form['fecha_ingreso']
        fecha_ingreso = datetime.strptime(fecha_ingreso, "%d/%m/%Y")
        fecha_subida = request.form['fecha_subida']
        fecha_subida = datetime.strptime(fecha_subida, "%d/%m/%Y")
        base_imp = request.form['base_imp']
        iva = request.form['iva']
        total_ingreso = request.form['total_ingreso']
        archivo = request.files['archivo']
        archivo = archivo.read()
        n_archivo = request.files['archivo']
        nombre_archivo = n_archivo.filename
        estado_factura = request.form['estado_factura']
        id_factura_usuario = request.form['id_factura_usuario']

        new_factura_ingreso = Factura_ingreso(concepto, fecha_ingreso, fecha_subida,
                                              base_imp, iva, total_ingreso, archivo,
                                              nombre_archivo, estado_factura, id_factura_usuario)
        
        db.session.add(new_factura_ingreso)
        db.session.commit()

        # factura_ingreso = Factura_ingreso.query.get(new_factura_ingreso.id)

        # return factura_ingreso_schema.jsonify(factura_ingreso)

        return "factura subida exitosamente"


#EndPoint to query all exept "archivo" in table factura_ingreso
@app.route('/factura_ingreso/get/<id>', methods=["GET"])
def get_facturas_ingresos(id):
    query = db.session.execute(db.select(Factura_ingreso.id,Factura_ingreso.concepto, Factura_ingreso.fecha_ingreso, Factura_ingreso.fecha_subida,
                       Factura_ingreso.base_imp, Factura_ingreso.iva, Factura_ingreso.total_ingreso, Factura_ingreso.nombre_archivo, 
                       Factura_ingreso.estado_factura, Factura_ingreso.id_factura_usuario).where(Factura_ingreso.id_factura_usuario == id))

    result = multi_factura_ingreso_schema.dump(query)
    return jsonify(result)


#EndPoint to query all exept "archivo" to edit factura_ingreso
@app.route('/factura_ingreso/get_edit/<id>', methods=["GET"])
def get_toedit_factura_ingreso(id):
    query = db.session.execute(db.select(Factura_ingreso.id,Factura_ingreso.concepto, Factura_ingreso.fecha_ingreso,Factura_ingreso.base_imp, 
                                         Factura_ingreso.iva, Factura_ingreso.total_ingreso).where(Factura_ingreso.id == id))

    result = multi_factura_ingreso_schema.dump(query)
    return jsonify(result)


#EndPoint for querying a single factura_ingreso
@app.route('/factura_ingreso/get/<id>', methods=["GET"])
def get_single_factura_ingreso(id):
     single_factura_ingreso = Factura_ingreso.query.get(id)
     return factura_ingreso_schema.jsonify(single_factura_ingreso)

#EndPoint for updating a factura_ingreso
@app.route('/factura_ingreso/update/<id>', methods=["PATCH"])
def factura_ingreso_update(id):
    factura_ingreso = db.session.get(Factura_ingreso, id)
    concepto = request.form['concepto']
    fecha_ingreso = request.form['fecha_ingreso']
    fecha_ingreso = datetime.strptime(fecha_ingreso, "%d/%m/%Y")
    base_imp = request.form['base_imp']
    iva = request.form['iva']
    total_ingreso = request.form['total_ingreso']
    archivo = request.files['archivo']
    archivo = archivo.read()
    n_archivo = request.files['archivo']
    nombre_archivo = n_archivo.filename

    factura_ingreso.concepto = concepto
    factura_ingreso.fecha_ingreso = fecha_ingreso
    factura_ingreso.base_imp = base_imp
    factura_ingreso.iva = iva
    factura_ingreso.total_ingreso = total_ingreso
    factura_ingreso.archivo = archivo
    factura_ingreso.nombre_archivo = nombre_archivo
    
    db.session.commit()
    return "factura actualizada exitosamente"



#EndPoint for deleting a record
@app.route('/factura_ingreso/delete/<id>', methods=["DELETE"])
def factura_ingreso_delete(id):
    factura_ingreso = Factura_ingreso.query.get(id)
    db.session.delete(factura_ingreso)
    db.session.commit()

    return "La Factura de Ingreso se elimino correctamente!"

#EndPoint for Download a Invoice Ingreso
@app.route('/factura_ingreso/download/<down_id>', methods=["GET"])
def factura_ingreso_download(down_id):
    download = Factura_ingreso.query.filter_by(id=down_id).first()
    return send_file(BytesIO(download.archivo), download_name=download.nombre_archivo, as_attachment=True)

#EndPoint for accept facturas ingreso
@app.route('/factura_ingreso/accept/<id>', methods=["PUT"])
def accept_factura_ingreso(id):
    factura_ingreso = Factura_ingreso.query.get(id)
    estado_factura = "ACEPTADA"

    factura_ingreso.estado_factura = estado_factura

    db.session.commit()
    return "Factura aceptada con exito"

#EndPoint for reject facturas ingreso
@app.route('/factura_ingreso/rejected/<id>', methods=["PUT"])
def rejected_factura_ingreso(id):
    factura_ingreso = Factura_ingreso.query.get(id)
    estado_factura = "RECHAZADA"

    factura_ingreso.estado_factura = estado_factura

    db.session.commit()
    return "Factura rechazada con exito"


############################################## FACTURAS GASTOS ####################################################################     
#Table Factura_gasto and EndPoints
class Factura_gasto(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    concepto = db.Column(db.String (100), nullable=False)
    fecha_gasto = db.Column(db.Date, nullable=False)
    fecha_subida = db.Column(db.Date, nullable=False)
    base_imp = db.Column(db.Integer, nullable=False)
    iva = db.Column(db.Integer, nullable=False)
    total_gasto = db.Column(db.Integer, nullable=False)
    archivo = db.Column(db.LargeBinary, nullable=False)
    nombre_archivo = db.Column(db.VARCHAR(100), nullable=False)
    estado_factura = db.Column(db.String, nullable=False)
    id_factura_usuario = db.Column(db.Integer)

    def __init__(self, concepto, fecha_gasto, fecha_subida, base_imp, iva, 
                 total_gasto, archivo,nombre_archivo, estado_factura, id_factura_usuario):
        self.concepto = concepto
        self.fecha_gasto = fecha_gasto
        self.fecha_subida = fecha_subida
        self.base_imp = base_imp
        self.iva = iva
        self.total_gasto = total_gasto
        self.archivo = archivo
        self.nombre_archivo = nombre_archivo
        self.estado_factura = estado_factura
        self.id_factura_usuario = id_factura_usuario


class Factura_gastoSchema(ma.Schema):
    class Meta:
        fields = ('id','concepto','fecha_gasto','fecha_subida','base_imp','iva',
                  'total_gasto','archivo','nombre_archivo','estado_factura','id_factura_usuario')
        
factura_gasto_schema = Factura_gastoSchema()
multi_factura_gasto_schema = Factura_gastoSchema(many=True)

# EndPoint to create a new factura_gasto
@app.route('/factura_gasto/add', methods=["POST"])
def add_factura_gasto():
    
        concepto = request.form['concepto']
        fecha_gasto = request.form['fecha_gasto']
        fecha_gasto = datetime.strptime(fecha_gasto, "%d/%m/%Y")
        fecha_subida = request.form['fecha_subida']
        fecha_subida = datetime.strptime(fecha_subida, "%d/%m/%Y")
        base_imp = request.form['base_imp']
        iva = request.form['iva']
        total_gasto = request.form['total_gasto']
        archivo = request.files['archivo']
        archivo = archivo.read()
        n_archivo = request.files['archivo']
        nombre_archivo = n_archivo.filename
        estado_factura = request.form['estado_factura']
        id_factura_usuario = request.form['id_factura_usuario']

        new_factura_gasto = Factura_gasto(concepto, fecha_gasto, fecha_subida,
                                              base_imp, iva, total_gasto, archivo,
                                              nombre_archivo, estado_factura, id_factura_usuario)
        
        db.session.add(new_factura_gasto)
        db.session.commit()

        # factura_gasto = Factura_gasto.query.get(new_factura_gasto.id)
        # return factura_gasto_schema.jsonify(factura_gasto)

        return "Factura subida exitosamente"


#EndPoint to query all exept "archivo" in table factura_gasto
@app.route('/factura_gasto/get/<id>', methods=["GET"])
def get_facturas_gastos(id):
    query = db.session.execute(db.select(Factura_gasto.id,Factura_gasto.concepto, Factura_gasto.fecha_gasto, Factura_gasto.fecha_subida,
                       Factura_gasto.base_imp, Factura_gasto.iva, Factura_gasto.total_gasto, Factura_gasto.nombre_archivo, 
                       Factura_gasto.estado_factura, Factura_gasto.id_factura_usuario).where(Factura_gasto.id_factura_usuario == id))

    result = multi_factura_gasto_schema.dump(query)
    return jsonify(result)

#EndPoint to query all exept "archivo" to edit factura_gasto
@app.route('/factura_gasto/get_edit/<id>', methods=["GET"])
def get_toedit_factura_gasto(id):
    query = db.session.execute(db.select(Factura_gasto.id,Factura_gasto.concepto, Factura_gasto.fecha_gasto,Factura_gasto.base_imp, 
                                         Factura_gasto.iva, Factura_gasto.total_gasto).where(Factura_gasto.id == id))

    result = multi_factura_gasto_schema.dump(query)
    return jsonify(result)


#EndPoint for querying a single factura_gasto
@app.route('/factura_gasto/get/<id>', methods=["GET"])
def get_single_factura_gasto(id):
     single_factura_gasto = Factura_gasto.query.get(id)
     return factura_gasto_schema.jsonify(single_factura_gasto)



#EndPoint for updating a factura_gasto
@app.route('/factura_gasto/update/<id>', methods=["PATCH"])
def factura_gasto_update(id):
    factura_gasto = db.session.get(Factura_gasto, id)
    concepto = request.form['concepto']
    fecha_gasto = request.form['fecha_gasto']
    fecha_gasto = datetime.strptime(fecha_gasto, "%d/%m/%Y")
    base_imp = request.form['base_imp']
    iva = request.form['iva']
    total_gasto = request.form['total_gasto']
    archivo = request.files['archivo']
    archivo = archivo.read()
    n_archivo = request.files['archivo']
    nombre_archivo = n_archivo.filename

    factura_gasto.concepto = concepto
    factura_gasto.fecha_ingreso = fecha_gasto
    factura_gasto.base_imp = base_imp
    factura_gasto.iva = iva
    factura_gasto.total_ingreso = total_gasto
    factura_gasto.archivo = archivo
    factura_gasto.nombre_archivo = nombre_archivo

    db.session.commit()
    return "factura actualizada exitosamente"

#EndPoint for deleting a record
@app.route('/factura_gasto/delete/<id>', methods=["DELETE"])
def factura_gasto_delete(id):
    factura_gasto = Factura_gasto.query.get(id)
    db.session.delete(factura_gasto)
    db.session.commit()

    return "La Factura de Gasto se elimino correctamente!"


#EndPoint for Download a Invoice Gasto
@app.route('/factura_gasto/download/<down_id>', methods=["GET"])
def factura_gasto_download(down_id):
    download = Factura_gasto.query.filter_by(id=down_id).first()
    return send_file(BytesIO(download.archivo), download_name=download.nombre_archivo, as_attachment=True)

#EndPoint for accept facturas gasto
@app.route('/factura_gasto/accept/<id>', methods=["PUT"])
def accept_factura_gasto(id):
    factura_gasto = Factura_gasto.query.get(id)
    estado_factura = "ACEPTADA"

    factura_gasto.estado_factura = estado_factura

    db.session.commit()
    return "Factura aceptada con exito"

#EndPoint for reject facturas gasto
@app.route('/factura_gasto/rejected/<id>', methods=["PUT"])
def rejected_factura_gasto(id):
    factura_gasto = Factura_gasto.query.get(id)
    estado_factura = "RECHAZADA"

    factura_gasto.estado_factura = estado_factura

    db.session.commit()
    return "Factura rechazada con exito"


############################################## DOCUMENTOS #################################################################### 
#Table Documentos and EndPoints
class Documentos(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombre_documento = db.Column(db.VARCHAR (70), nullable=False)
    comentario = db.Column(db.VARCHAR(100), nullable=False)
    documento = db.Column(db.LargeBinary, nullable=False)
    nombre_file = db.Column(db.VARCHAR(100), nullable=False)
    fecha_subida = db.Column(db.Date, nullable=False)
    id_rol_upload = db.Column(db.Integer)
    id_documento_user= db.Column(db.Integer)

    def __init__(self, nombre_documento, comentario, documento, nombre_file ,fecha_subida, id_rol_upload, id_documento_user):
        self.nombre_documento = nombre_documento
        self.comentario = comentario
        self.documento = documento
        self.nombre_file = nombre_file
        self.fecha_subida = fecha_subida
        self.id_rol_upload = id_rol_upload
        self.id_documento_user = id_documento_user


class DocumentoSchema(ma.Schema):
    class Meta:
        fields = ('id','nombre_documento','comentario','documento','nombre_file','fecha_subida','id_rol_upload','id_documento_user')
        
documento_schema = DocumentoSchema()
multi_documento_schema = DocumentoSchema(many=True)


# EndPoint to create a new documento
@app.route('/documento/add', methods=["POST"])
def add_documento():
    
        nombre_documento = request.form['nombre']
        comentario = request.form['comentario']
        documento = request.files['documento']
        documento = documento.read()
        n_file = request.files['documento']
        nombre_file= n_file.filename
        fecha_subida = request.form['fecha_subida']
        fecha_subida = datetime.strptime(fecha_subida, "%d/%m/%Y")
        id_rol_upload = request.form['rol_upload']
        id_documento_user = request.form['id_documento_user']

        new_documento = Documentos(nombre_documento, comentario, documento, nombre_file, fecha_subida, id_rol_upload, id_documento_user)
        
        db.session.add(new_documento)
        db.session.commit()

        return ("Documento subido exitosamente"),200

#EndPoint to query all exept "file" in table documentos
@app.route('/documento/get/<id>', methods=["GET"])
def get_documentos(id):
    query = db.session.execute(db.select(Documentos.id, Documentos.nombre_documento, Documentos.comentario, 
                                        Documentos.fecha_subida, Documentos.id_rol_upload).where(Documentos.id_documento_user == id))

    result = multi_documento_schema.dump(query)
    return jsonify(result), 200

#EndPoint for Download a Documento File
@app.route('/documento/download/<down_id>', methods=["GET"])
def documento_download(down_id):
    download = Documentos.query.filter_by(id=down_id).first()
    return send_file(BytesIO(download.documento), download_name=download.nombre_file, as_attachment=True)

#EndPoint for deleting a documento
@app.route('/documento/delete/<id>', methods=["DELETE"])
def documento_delete(id):
    documento = Documentos.query.get(id)
    db.session.delete(documento)
    db.session.commit()

    return ("El documento se elimino correctamente!"), 200


############################################## ENDPOINTS IMPUESTOS ####################################################################

#EndPoint Sum Total Factura Ingreso
@app.route('/factura_ingreso/sum_totalingreso/<id>', methods=["GET"])
def get_sum_totalingreso(id):

    query = db.session.query(func.sum(Factura_ingreso.total_ingreso)).where(Factura_ingreso.id_factura_usuario == id,
                                                                            Factura_ingreso.estado_factura == "ACEPTADA").scalar()
    return jsonify(query)

#EndPoint Sum IVA Factura Ingreso
@app.route('/factura_ingreso/sum_ivaingreso/<id>', methods=["GET"])
def get_sum_ivaingreso(id):

    query = db.session.query(func.sum(Factura_ingreso.iva)).where(Factura_ingreso.id_factura_usuario == id,
                                                                  Factura_ingreso.estado_factura == "ACEPTADA" ).scalar()
    return jsonify(query)


#EndPoint Sum Total Factura Gasto
@app.route('/factura_gasto/sum_totalgasto/<id>', methods=["GET"])
def get_sum_totalgasto(id):

    query = db.session.query(func.sum(Factura_gasto.total_gasto)).where(Factura_gasto.id_factura_usuario == id, 
                                                                        Factura_gasto.estado_factura == "ACEPTADA" ).scalar()
    return jsonify(query)

#EndPoint Sum IVA Factura Gasto
@app.route('/factura_gasto/sum_ivagasto/<id>', methods=["GET"])
def get_sum_ivagasto(id):

    query = db.session.query(func.sum(Factura_gasto.iva)).where(Factura_gasto.id_factura_usuario == id,
                                                                Factura_gasto.estado_factura == "ACEPTADA").scalar()
    return jsonify(query)


# #EndPoint Get Trimestre
# @app.route('/factura_ingreso/get_trimestre', methods=["GET"])
# def get_tri_factura_ingreso():
#     query = db.session.execute(db.select(Factura_ingreso.base_imp,Factura_ingreso.iva, Factura_ingreso.total_ingreso
#                                          ).where(Factura_ingreso.fecha_ingreso.between('2023-08-01', '2023-10-31')))

#     result = multi_factura_ingreso_schema.dump(query)
#     return jsonify(result)


if __name__ == '__main__':
    app.run(debug=True)