from io import BytesIO
import json
from flask import Flask, request, jsonify, send_file
from datetime import timedelta, datetime
from flask_sqlalchemy import SQLAlchemy
# import re 
from sqlalchemy.dialects.sqlite import DATE
from flask_marshmallow import Marshmallow
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import (create_access_token,  get_jwt_identity, jwt_required, JWTManager)
import os

app = Flask(__name__)
CORS(app, supports_credentials=True, expose_headers=["Content-Disposition"])


basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI']= 'sqlite:///' + os.path.join(basedir, 'app.sqlite')
db = SQLAlchemy(app)
ma = Marshmallow(app)
bc = Bcrypt(app)
# d = DATE(
#             storage_format="%(day)02d/%(month)02d/%(year)04d",
#             regexp=re.compile("(?P<day>\d+)/(?P<month>\d+)/(?P<year>\d+)")
#         )

app.config['JWT_TOKEN_LOCATION'] = ["headers", "cookies"]
app.config['JWT_COOKIE_CSRF_PROTECT'] = False
app.config["JWT_COOKIE_SECURE"] = True
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=3)
#app.config['JWT_ACCESS_COOKIE_PATH'] = '/prueba'

# Create Secret KEY
app.config["JWT_SECRET_KEY"] = "D5*F?_1?-d$f*1_Sndjñ2*$dsj"
jwt = JWTManager(app)


#Table users and EndPoints
class Usuarios(db.Model):
    id_usuario = db.Column(db.Integer, primary_key=True)
    nombre_usuario = db.Column(db.String(50), nullable=False, unique=False)
    apellidos_usuario = db.Column(db.String(60), nullable=False, unique=False)
    email_usuario = db.Column(db.VARCHAR(60), nullable=False, unique=True)
    password = db.Column(db.VARCHAR(15), nullable=False, unique=False)
    telefono_usuario = db.Column(db.Integer, nullable=False, unique=False)
    direccion_usuario = db.Column(db.VARCHAR(100), nullable=False, unique=False)
    id_rol_usuario = db.Column(db.Integer, nullable=False, unique=False)

    def __init__(self, nombre_usuario, apellidos_usuario, email_usuario,
                password, telefono_usuario, direccion_usuario, id_rol_usuario):
        self.nombre_usuario = nombre_usuario
        self.apellidos_usuario = apellidos_usuario
        self.email_usuario = email_usuario
        self.password = password
        self.telefono_usuario = telefono_usuario
        self.direccion_usuario = direccion_usuario
        self.id_rol_usuario = id_rol_usuario

class UsuariosSchema(ma.Schema):
    class Meta:
        fields = ('nombre_usuario', 'apellidos_usuario', 'email_usuario',
                  'password','telefono_usuario', 'direccion_usuario', 'id_rol_usuario')
        
usuarios_schema = UsuariosSchema()
multi_usuarios_schema = UsuariosSchema(many=True)


# EndPoint to create a new user
@app.route('/usuario/add', methods=["POST"])
def add_usuario():
    
        nombre_usuario = request.json['nombre_usuario']
        apellidos_usuario = request.json['apellidos_usuario']
        email_usuario = request.json['email_usuario']
        password = request.json['password']
        telefono_usuario = request.json['telefono_usuario']
        direccion_usuario = request.json['direccion_usuario']
        id_rol_usuario = request.json['id_rol_usuario']

        pw_hash = bc.generate_password_hash(password, 15).decode('utf-8')
        
        new_usuario = Usuarios(nombre_usuario, apellidos_usuario, email_usuario,
                                pw_hash, telefono_usuario, direccion_usuario, id_rol_usuario)
        
        db.session.add(new_usuario)
        db.session.commit()

        usuario = Usuarios.query.get(new_usuario.id_usuario)
        return usuarios_schema.jsonify(usuario)


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


#EndPoint for querying a single user
@app.route('/usuario/get/<id>', methods=["GET"])
def get_single_usuario(id):
    single_usuario = Usuarios.query.get(id)
    return usuarios_schema.jsonify(single_usuario), 200


#EndPoint for updating a user
@app.route('/usuario/update/<id>', methods=["PUT"])
def usuario_update(id):
    usuario = Usuarios.query.get(id)
    nombre_usuario = request.json['nombre_usuario']
    apellidos_usuario = request.json['apellidos_usuario']
    email_usuario = request.json['email_usuario']
    password = request.json['password']
    telefono_usuario = request.json['telefono_usuario']
    direccion_usuario = request.json['direccion_usuario']
    id_rol_usuario = request.json['id_rol_usuario']

    usuario.nombre_usuario = nombre_usuario
    usuario.apellidos_usuario = apellidos_usuario
    usuario.email_usuario = email_usuario
    usuario.password = password
    usuario.telefono_usuario = telefono_usuario
    usuario.direccion_usuario = direccion_usuario
    usuario.id_rol_usuario = id_rol_usuario

    db.session.commit()
    return usuarios_schema.jsonify(usuario)

#EndPoint for deleting a user
@app.route('/usuario/delete/<id>', methods=["DELETE"])
def usuario_delete(id):
    usuario = Usuarios.query.get(id)
    db.session.delete(usuario)
    db.session.commit()

    return "El usuario se ha eliminado correctamente!"


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
@app.route('/factura_ingreso/get', methods=["GET"])
def get_facturas_ingresos():
    query = db.session.execute(db.select(Factura_ingreso.id,Factura_ingreso.concepto, Factura_ingreso.fecha_ingreso, Factura_ingreso.fecha_subida,
                       Factura_ingreso.base_imp, Factura_ingreso.iva, Factura_ingreso.total_ingreso, Factura_ingreso.nombre_archivo, 
                       Factura_ingreso.estado_factura, Factura_ingreso.id_factura_usuario))

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
    # factura_ingreso = Factura_ingreso.query.get(id)
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

#EndPoint for Download a Invoice
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
    concepto = db.Column(db.String (100), nullable=False, unique=False)
    fecha_gasto = db.Column(db.String, nullable=False, unique=False)
    fecha_subida = db.Column(db.String, nullable=False, unique=False)
    base_imp = db.Column(db.Integer, nullable=False, unique=False)
    iva = db.Column(db.Integer, nullable=False, unique=False)
    total_gasto = db.Column(db.Integer, nullable=False, unique=False)
    archivo = db.Column(db.String, nullable=False, unique=False)
    estado_factura = db.Column(db.String, nullable=False, unique=False)
    id_factura_usuario = db.Column(db.Integer)

    def __init__(self, concepto, fecha_gasto, fecha_subida, base_imp, iva, 
                 total_gasto, archivo, estado_factura, id_factura_usuario):
        self.concepto = concepto
        self.fecha_gasto = fecha_gasto
        self.fecha_subida = fecha_subida
        self.base_imp = base_imp
        self.iva = iva
        self.total_gasto = total_gasto
        self.archivo = archivo
        self.estado_factura = estado_factura
        self.id_factura_usuario = id_factura_usuario


class Factura_gastoSchema(ma.Schema):
    class Meta:
        fields = ('id','concepto','fecha_gasto','fecha_subida','base_imp','iva',
                  'total_gasto','archivo','estado_factura','id_factura_usuario')
        
factura_gasto_schema = Factura_gastoSchema()
multi_factura_gasto_schema = Factura_gastoSchema(many=True)

# EndPoint to create a new factura_gasto
@app.route('/factura_gasto/add', methods=["POST"])
def add_factura_gasto():
    
        concepto = request.json['concepto']
        fecha_gasto = request.json['fecha_gasto']
        fecha_subida = request.json['fecha_subida']
        base_imp = request.json['base_imp']
        iva = request.json['iva']
        total_gasto = request.json['total_gasto']
        archivo = request.json['archivo']
        estado_factura = request.json['estado_factura']
        id_factura_usuario = request.json['id_factura_usuario']

        new_factura_gasto = Factura_gasto(concepto, fecha_gasto, fecha_subida,
                                              base_imp, iva, total_gasto, archivo,
                                              estado_factura, id_factura_usuario)
        
        db.session.add(new_factura_gasto)
        db.session.commit()

        factura_gasto = Factura_gasto.query.get(new_factura_gasto.id)

        return factura_gasto_schema.jsonify(factura_gasto)

#EndPoint to query all factura_gasto
@app.route('/factura_gasto/get', methods=["GET"])
def get_facturas_gastos():
    all_facturas_gastos = Factura_gasto.query.all()
    result = multi_factura_gasto_schema.dump(all_facturas_gastos)
    return jsonify(result)

#EndPoint for querying a single factura_gasto
@app.route('/factura_gasto/get/<id>', methods=["GET"])
def get_single_factura_gasto(id):
     single_factura_gasto = Factura_gasto.query.get(id)
     return factura_gasto_schema.jsonify(single_factura_gasto)

#EndPoint for updating a factura_gasto
@app.route('/factura_gasto/update/<id>', methods=["PUT"])
def factura_gasto_update(id):
    factura_gasto = Factura_gasto.query.get(id)
    concepto = request.json['concepto']
    fecha_gasto = request.json['fecha_gasto']
    fecha_subida = request.json['fecha_subida']
    base_imp = request.json['base_imp']
    iva = request.json['iva']
    total_gasto = request.json['total_gasto']
    archivo = request.json['archivo']
    estado_factura = request.json['estado_factura']
    id_factura_usuario = request.json['id_factura_usuario']

    factura_gasto.concepto = concepto
    factura_gasto.fecha_gasto = fecha_gasto
    factura_gasto.fecha_subida = fecha_subida
    factura_gasto.base_imp = base_imp
    factura_gasto.iva = iva
    factura_gasto.total_gasto = total_gasto
    factura_gasto.archivo = archivo
    factura_gasto.estado_factura = estado_factura
    factura_gasto.id_factura_usuario = id_factura_usuario

    db.session.commit()
    return factura_gasto_schema.jsonify(factura_gasto)

#EndPoint for deleting a record
@app.route('/factura_gasto/delete/<id>', methods=["DELETE"])
def factura_gasto_delete(id):
    factura_gasto = Factura_gasto.query.get(id)
    db.session.delete(factura_gasto)
    db.session.commit()

    return "La Factura de Gasto se elimino correctamente!"

if __name__ == '__main__':
    app.run(debug=True)