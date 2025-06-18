
import datetime
import jwt
import uuid
import hashlib
from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_admin import Admin
from sqlalchemy import Enum
from functools import wraps
from flask_admin.contrib.sqla import ModelView
from wtforms.fields import PasswordField
from wtforms.validators import ValidationError
from flask_admin.form import Select2Widget
from wtforms import FileField, SelectField
from wtforms.widgets import Select as Select2Widget
from markupsafe import Markup
import base64


app = Flask(__name__)

app.config['SECRET_KEY'] = "thisissecret"
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:123456@localhost:5433/postgres'

db = SQLAlchemy(app)
admin = Admin(app)

class Users(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(100), unique=True)
    name = db.Column(db.String(100), nullable=False)
    surname = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(100))
    admin = db.Column(db.Boolean)

    def set_password(self, password):
        self.password = hashlib.sha256(password.encode('utf-8')).hexdigest()

    def check_password(self, password):
        return self.password == hashlib.sha256(password.encode('utf-8')).hexdigest()
   

class Product(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(100), unique=True)
    name = db.Column(db.String(100), nullable=False)
    count = db.Column(db.Integer)
    category = db.Column(Enum('Oziq-ovqat', 'Elektronika', 'Maishiy texnika', name='product_category'), nullable=False)
    image = db.Column(db.Text, nullable=False)



class UserAdminView(ModelView):
    form_columns = ['name', 'surname','email', 'password']
    form_extra_fields = {'password': PasswordField('Parol')}

    can_delete = True

    def validate_form(self, form):
        existing = None  

        if hasattr(form, 'email') and form.email.data:
            email = form.email.data
            existing = Users.query.filter_by(email=email).first()
            current_id = None

        if hasattr(form, '_obj') and form._obj:
            current_id = form._obj.id

        if existing and (not current_id or existing.id != current_id):
            raise ValidationError('Bu email allaqachon ro‘yxatdan o‘tgan!')

        return super().validate_form(form)



    def on_model_change(self, form, model, is_create):
        if is_create and not model.public_id:
            model.public_id = str(uuid.uuid4())
            model.admin = False
        
        if form.password.data:
            model.set_password(form.password.data)
        super().on_model_change(form, model, is_create)

    form_extra_fields = {
        'password': PasswordField('Parol')
    }



admin.add_view(UserAdminView(Users, db.session, name='Foydalanuvchilar'))

class ProductModelView(ModelView):
    column_list = ('name', 'count', 'category', 'image') 

    column_formatters = {
        'image': lambda v, c, m, p: Markup(f'<img src="{m.image}" width="100">') if m.image else ''
    }

    form_columns = ('name', 'count', 'category', 'image_file')

    form_overrides = {
        'category': SelectField
    }

    form_args = {
        'category': {
            'choices': [
                ('Oziq-ovqat', 'Oziq-ovqat'),
                ('Elektronika', 'Elektronika'),
                ('Maishiy texnika', 'Maishiy texnika')
            ],
            'widget': Select2Widget()
        }
    }

    form_extra_fields = {
        'image_file': FileField('Image')
    }

    def on_model_change(self, form, model, is_create):
        image_file = form.image_file.data
        if image_file:
            data = image_file.read()
            model.image = f"data:{image_file.mimetype};base64," + base64.b64encode(data).decode('utf-8')
        if is_create and not model.public_id:
            model.public_id = str(uuid.uuid4())

admin.add_view(ProductModelView(Product, db.session))


def token_required(f):  
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'token' in request.headers:
            token = request.headers['token']

        if not token:
            return jsonify({'message' : 'Token is missing!'}), 401
       
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = Users.query.filter_by(public_id=data['public_id']).first()
        except Exception as e:
            return jsonify({'message': 'Token is invalid', 'error': str(e)}), 404
        

        return f(current_user, *args, **kwargs)

    return decorated

@app.route("/")  # H O M E 
def home():
    return jsonify({"message": "Xush kelibsiz!"}), 200


@app.route("/user", methods=['GET']) # G E T   A L L
@token_required
def get_all_users(current_user):

    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'}), 403
    
    users = Users.query.all()
    data = []

    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['name'] =  user.name
        user_data['surname'] = user.surname
        user_data['email'] = user.email
        user_data['password'] = user.password
        user_data['ADMIN'] = user.admin
        data.append(user_data)

    return jsonify({'users' : data}), 200

@app.route("/user/<public_id>", methods=['GET'])  # G E T    O N E
@token_required
def get_one_user(current_user, public_id):

    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'}), 403

    user = Users.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message' : 'User not found!'})
    
    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['name'] =  user.name
    user_data['surname'] = user.surname
    user_data['email'] = user.email
    user_data['password'] = user.password
    user_data['ADMIN'] = user.admin

    return jsonify({'users' : user_data}), 200

@app.route("/user", methods=['POST']) # C R E A T E 
@token_required
def create_user(current_user):

    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'}), 403

    data = request.get_json()
    name = data["name"]
    surname = data["surname"]
    email = data["email"]
    password = data["password"]
    conf_password = data["conf_password"]

    existing_user = Users.query.filter_by(email=email).first()
    if existing_user:
        return jsonify({"message": "Bunday emailga ega foydalanuvchi mavjud!"}), 400

    if conf_password != password :
        return jsonify({"message": "Parollar mos kelmadi!"}) , 400
    
    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    new_user = Users(public_id=str(uuid.uuid4()),name=name, surname=surname, email=email, password=hashed_password, admin=False)
    
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'New user created!'}), 201


@app.route("/user/<public_id>", methods=['PUT']) # A D M I N
@token_required
def promote_user(current_user, public_id):

    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'}), 403

    user = Users.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message' : 'User not found!'}), 404
    
    user.admin = True
    db.session.commit()

    return jsonify({'message' : 'The user has been promoted!'}), 200

@app.route("/user/update/<public_id>", methods=['PUT'])  # U P D A T E
@token_required
def update_user(current_user, public_id):

    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'}), 403 

    user = Users.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message' : 'User not found!'}), 404
    
    data = request.get_json()
    
    name = data["name"]
    surname = data["surname"]
    email = data["email"]
    password = data["password"]
    conf_password = data["conf_password"]

    existing_user = Users.query.filter_by(email=email).first()
    if existing_user:
        return jsonify({"message": "Bunday emailga ega foydalanuvchi mavjud!"}), 400

    if conf_password != password :
        return jsonify({"message": "Parollar mos kelmadi!"}), 400
    
    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    Users.query.filter_by(public_id=public_id).update({Users.name: name, Users.surname: surname, Users.email: email, Users.password: hashed_password}, synchronize_session=False)
    db.session.commit()
        
    return jsonify({"message": "Foydalanuvchining ma'lumotlari muvaffaqiyatli yangilandi!"}), 200



@app.route("/user/<public_id>", methods=['DELETE']) #  D E L E T E
@token_required
def delete_user(current_user, public_id):

    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'}), 403

    user = Users.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message' : 'User not found!'}), 404
    
    db.session.delete(user)
    db.session.commit()

    return jsonify({'message' : 'The user has been deleted!'}), 200

@app.route("/sign-in", methods=['POST'])  # S I G N - I N
def sign_in():

    data = request.get_json()
    email = data["email"]
    password = data["password"]
    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    user = Users.query.filter_by(email=email).first()
    if not user or user.password != hashed_password:
        return jsonify({'message' : 'Email or password is incorrect!'}), 400
    
    token = jwt.encode({'public_id': user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'], algorithm="HS256")

    return jsonify({'token' : token}), 200

@app.route("/sign-up", methods=['POST']) # S I G N - U P
def sign_up():

    data = request.get_json()
    name = data["name"]
    surname = data["surname"]
    email = data["email"]
    password = data["password"]
    conf_password = data["conf_password"]

    existing_user = Users.query.filter_by(email=email).first()
    if existing_user:
        return jsonify({"message": "Bunday emailga ega foydalanuvchi mavjud!"}), 400

    if conf_password != password :
        return jsonify({"message": "Parollar mos kelmadi!"}), 400
    
    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    new_user = Users(public_id=str(uuid.uuid4()),name=name, surname=surname, email=email, password=hashed_password, admin=False)
    
    db.session.add(new_user)
    db.session.commit()

    token = jwt.encode({'public_id': new_user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'], algorithm="HS256")

    return jsonify({'token' : token}), 201

@app.route("/product", methods=['GET']) # G E T  A L L   P R O D U C T S
@token_required
def get_products(current_user):
    
    products = Product.query.all()
    data = []

    for product in products:
        product_data = {}
        product_data['name'] =  product.name
        product_data['count'] = product.count
        product_data['category'] = product.category
        product_data['public_id'] = product.public_id
        data.append(product_data)

    return jsonify({'products' : data}), 200

@app.route("/product/<category>", methods=['GET']) # F I L T E R   A L L   P R O D U C T S   B Y   C A T E G O R I E S
@token_required
def filter_products(current_user, category):

    products = Product.query.filter_by(category=category)
    
    data = []

    for product in products:
        product_data = {}
        product_data['name'] =  product.name
        product_data['count'] = product.count
        product_data['category'] = product.category
        product_data['public_id'] = product.public_id
        data.append(product_data)

    return jsonify({'products' : data}), 200


@app.route("/product/add-product", methods=['POST']) #  C R E A T E   P R O D U C T 
@token_required
def add_product(current_user):


    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'}), 403
    

    data = request.get_json()
    name = data["name"]
    count = data["count"]
    category = data["category"]
    image = data["image"]
    public_id = str(uuid.uuid4())

    exsiting_product = Product.query.filter_by(public_id=public_id).first()
    if exsiting_product:
        return jsonify({'message' : 'Bunday mahsulot allaqachon mavjud!'}), 400
    
    new_product = Product(name=name, count=count, category=category, image=image, public_id=public_id)
    db.session.add(new_product)
    db.session.commit()

    return jsonify({'message' : "Mahsulot muvaffaqiyatli qo'shildi"}), 201


@app.route("/product/change-count/<public_id>", methods=['PUT']) # C H A N G E  C O U N T
@token_required
def change_count(current_user, public_id):


    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'}), 403
    

    data = request.get_json()
    count = int(data['count'])

    exsiting_product = Product.query.filter_by(public_id=public_id).first() 

    if not exsiting_product:
        return jsonify({'message' : 'Bunday mahsulot topilmadi!'}), 400
    
    Product.query.filter_by(public_id=public_id).update({Product.count: Product.count + count}, synchronize_session=False)
    db.session.commit()
    
    return jsonify({'message' : 'Mahsulot miqdori muvaffaqiyatli yangilandi!'}), 200


@app.route("/product/<public_id>", methods=['DELETE']) # D E L E T E
@token_required
def delete_product(current_user, public_id):

    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'}), 403

    product = Product.query.filter_by(public_id=public_id).first()

    if not product:
        return jsonify({'message' : 'Product not found!'}), 400
    
    db.session.delete(product)
    db.session.commit()

    return jsonify({'message' : 'The product has been deleted!'}), 200


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(port=4200, debug=True)
