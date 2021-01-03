import csv
from flask import Flask, session, redirect, render_template, flash, request
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Email, Length, regexp, equal_to
from wtforms.fields.html5 import EmailField

app = Flask(__name__)
app.secret_key = 'assignment'
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
app.config['USE_SESSION_FOR_NEXT'] = True


class User(UserMixin):
    def __init__(self, fname, lname, username, email, password=None):
        self.id = username
        self.Last_Name = lname
        self.First_Name = fname
        self.email = email
        self.Password = password

    @property
    def is_authenticated(self):
        return True


@login_manager.user_loader
def load_user(user_id):
    user = find_user(user_id)
    return user


@app.route('/')
def base():
    return render_template("Base.html", username=session.get('username'))


@app.route('/silverware')
def silverware():
    if session.get('username') is None:
        flash('You need to be logged in to view this page')
        return redirect('/login')
    return render_template("Silverware.html", username=session.get('username'))


@app.route('/player')
def player():
    return render_template("Player.html", username=session.get('username'))


@app.route('/manager')
def manager():
    return render_template("Manager.html", username=session.get('username'))


class SignInForm(FlaskForm):
    Username = StringField('Username',
                           validators=[InputRequired(),
                                       Length(4, 64),
                                       regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0,
                                              'Usernames must start with a letter and must have only letters, numbers, '
                                              'dots or underscores')])
    First_Name = StringField('First Name', validators=[InputRequired()])
    Last_Name = StringField('Last Name', validators=[InputRequired()])
    Email = EmailField('Email', validators=[InputRequired(), Email()])
    Password = PasswordField('Password', validators=[InputRequired(),
                                                     Length(8)])
    Password2 = PasswordField('Repeat Password',
                              validators=[InputRequired(),
                                          equal_to('Password', message='Passwords must match.')])
    submit = SubmitField('Sign Up')

    def validate_password(self, field):
        with open('static/commonpassowrds.txt') as f:
            for line in f.readlines():
                if field.data == line.strip():
                    raise ValueError('Your password is too common.')


def find_user(username):
    with open('data/userdata.csv') as f:
        for user in csv.reader(f):
            if username == user[0]:
                return User(*user)
    return None


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect('/')
    form = SignInForm()
    if form.validate_on_submit():
        user = find_user(form.Username.data)
        if not user:
            with open('data/userdata.csv', 'a') as f:
                writer = csv.writer(f)
                writer.writerow([form.Username.data, form.First_Name.data, form.Last_Name.data, form.Email.data,
                                 form.Password.data])
            return render_template('Success.html', form=request.form)
        else:
            flash('This username already exists, choose another one')
    return render_template("Signup.html", form=form)


class LoginForm(FlaskForm):
    Username = StringField('Username', validators=[InputRequired(),
                                                   Length(4, 64),
                                                   regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0,
                                                          'Usernames must start with a letter and must have only '
                                                          'letters, numbers, '
                                                          'dots or underscores')])
    Password = PasswordField('Password', validators=[InputRequired(), Length(8)])
    submit = SubmitField('submit')


def check_password(username, password):
    with open('data/userdata.csv') as f:
        for user in csv.reader(f):
            if username == user[0] and password == user[4]:
                return True
    return False


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect('/')
    form = LoginForm()
    if form.validate_on_submit():
        user = find_user(form.Username.data)
        if check_password(form.Username.data, form.Password.data):
            login_user(user, remember=True)
            session['username'] = form.Username.data
            flash('Logged in successfully')
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect('/')
        else:
            flash('Wrong username or password. Please try again')
    return render_template("Login.html", form=form)


@app.route('/success', methods=['POST'])
def success():
    return render_template("Success.html", form=request.form)


@app.route('/logout')
def logout():
    session['username'] = None
    logout_user()
    return redirect('/')


if __name__ == '__main__':
    app.run()
