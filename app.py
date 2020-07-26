from datetime import timedelta

from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager, jwt_required, create_access_token

app = Flask(__name__)

app.config["SECRET_KEY"] = "secret"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///twitch.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)
Migrate(app, db)

jwt = JWTManager(app)

class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String)
    email = db.Column(db.String, nullable=False, unique=True)
    password = db.Column(db.String)

    def __repr__(self):
        return f"Usuário: {self.name}"

@app.route("/login", methods=["GET", "POST"])
def login():
    data = request.get_json()
    
    user = User.query.filter_by(email=data["email"]).first()
    if not user:
        return jsonify({
            "msg": "usuário não existe"
        })

    if not check_password_hash(user.password, data["password"]):
        return jsonify({
            "msg": "Senha incorreta!"
        })
    
    payload = {
        "id": user.id,
    }
    access_token = create_access_token(payload, expires_delta=timedelta(minutes=2)) 
    return jsonify({
        "access_token": access_token,
        "statusCode": 201
    }), 201
    


@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()

    user = User()
    user.email = data["email"]
    user.name = data["name"]
    user.password = generate_password_hash(data["password"])

    db.session.add(user)
    
    try:
        db.session.commit()
        return jsonify({
            "name": user.name,
            "email": user.email,
        }), 201
    except Exception as error:
        print(error)
        return jsonify({
            "message": "Por algum motivo não conseguimos fazer o cadastro do usuário.",
            "statusCode": 500
        }), 500



@app.route("/protected")
@jwt_required
def protected():
    return "Rota protegida."
