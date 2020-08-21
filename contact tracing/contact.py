from flask import Flask, render_template, url_for, request, session, logging, redirect, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from passlib.hash import sha256_crypt
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user


import gc
from datetime import datetime



app=Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI']= 'sqlite:///posts.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False 
app.config['SECRET_KEY']='thisissecret'
Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()

login_manager.login_view = 'login'



all_posts = [

    {
        'title':'post 1',
        'content':'this is contente of poost 1.miiii',
        'author':'mike'
    },
    {
        'title':'post 2',
        'content':'this is content of poost 2.meee'
    }
]













class BlogPost(db.Model):
    id =db.Column (db.Integer, primary_key=True)
    title =db.Column (db.String(200), nullable=False)
    content=db.Column (db.Text, nullable=False)
    author =db.Column (db.String, nullable=False, default='N/A')
    date_posted =db.Column (db.DateTime, default= datetime.utcnow)

    def __repr__(self):
        return 'blog post' + str(self.id)



class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True )
    email = db.Column(db.String(15), unique=True)
    password = db.Column(db.String(80))

    def __repr__(self):
        return 'User' + str(self.id)












    

@app.route('/')
def index():
    return render_template('home.html')



@app.route('/posts', methods=['GET', 'POST'])
def posts():
    if request.method == 'POST':
        post_title = request.form['title']
        post_content = request.form['content']
        post_author = request.form[ 'author' ]
        new_post = BlogPost(title=post_title, content=post_content, author=post_author)
        db.session.add(new_post)
        db.session.commit()
        return redirect('/posts')
    else:
        all_posts = BlogPost.query.order_by(BlogPost.date_posted)
        return render_template('posts.html', posts=all_posts)
    








@app.route('/posts/delete/<int:id>')
def delete(id):
    post =logPost.query.get_or_404(id)
    db.session.delete(post)
    db.session.commit()
    return redirect('/posts')



@app.route('/posts/edit/<int:id>', methods=['GET', 'POST'])
def edit(id):
    
    
    post = BlogPost.query.get_or_404(id)
  
    
    if request.method == 'POST':
       
        post.title = request.form['title']
        post.content = request.form['content']
        post.author = request.form['author']
        
        db.session.commit()

        return redirect('/posts')
    else:
        return render_template('edit.html', posts = post)

   
@app.route('/posts/new/', methods=['GET', 'POST']) 
def new_post():

    
     if request.method == 'POST':
        post.title = request.form['title']
        post.content = request.form['content']
        post.author = request.form[ 'author' ]
        new_post = BlogPost(title=post_title, content=post_content, author=post_author)
        db.session.add(new_post)
        db.session.commit()
        return redirect('/posts')

     else:
          return render_template('new_post.html') 
       






class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=20)] )
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    remember_me = BooleanField('remember me')





@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data) :
                return redirect(url_for('covid'))

        return 'invalid username or password'        

        #return '<h1> ' + form.username.data + ' your password is ' + form.password.data 

    return render_template('login.html', form=form)
    



class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='invalid email'), Length( max=100 )])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=20)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])








@app.route('/sign_up', methods=['GET', 'POST'])  
def sign_up():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method="sha256")
        new_user = User(username = form.username.data, email = form.email.data, password = hashed_password)
        flash("registered")
        db.session.add(new_user)
        db.session.commit()
        flash('new user has been created')
        return redirect('/')
        #return '<h1> ' + form.username.data + 'your email is ' + form.email.data + 'and password entered is ' + form.password.data

    return render_template('sign_up.html', form=form)




@app.route('/covid_check', methods =['GET', 'POST'])

def covid():
    return render_template('covid_check.html')



@app.route('/covid_check/self_check', methods= ['GET', 'POST'])
def self_check():
    
    return render_template('self_check.html')








@app.route('/covid_check/background_check', methods= ['GET', 'POST'])
def background_check():
    return render_template('background_check.html')


   
  


   


  





        
      


if __name__ == "__main__":
    app.run(debug=True)
