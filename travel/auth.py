from flask import Blueprint, render_template, redirect, url_for, flash
from .forms import LoginForm, RegisterForm
from flask_login import login_user, login_required, logout_user
from flask_bcrypt import generate_password_hash, check_password_hash
from .models import User
from . import db

#create a blueprint
authbp = Blueprint('auth', __name__ )

@authbp.route('/register', methods=['GET', 'POST'])
def register():
    register_form = RegisterForm()

    if register_form.validate_on_submit():
        # Get data from the form
        uname = register_form.user_name.data
        pwd = register_form.password.data
        email = register_form.email_id.data
        
        # Check if the username already exists in the database
        user = db.session.scalar(db.select(User).where(User.name == uname))
        
        if user:  # If user already exists, flash an error message
            flash('Username already exists, please try another', 'danger')
            return redirect(url_for('auth.register'))
        
        # Hash the password to store securely
        pwd_hash = generate_password_hash(pwd)
        
        # Create a new User model instance
        new_user = User(name=uname, password_hash=pwd_hash, emailid=email)
        
        # Add the new user to the database session and commit the changes
        db.session.add(new_user)
        db.session.commit()
        
        # Flash a success message and redirect to the home page
        flash('You have successfully registered! Welcome!', 'success')
        return redirect(url_for('main.index'))
    
    # If the request method is GET, or form validation fails, re-render the registration form
    return render_template('user.html', form=register_form, heading='Register')


@authbp.route('/login', methods=['GET', 'POST'])
def login():
    login_form = LoginForm()
    error = None
    if(login_form.validate_on_submit()==True):
        #get the username and password from the database
        user_name = login_form.user_name.data
        password = login_form.password.data
        user = db.session.scalar(db.select(User).where(User.name==user_name))
        #if there is no user with that name
        if user is None:
            error = 'Incorrect username'#could be a security risk to give this much info away
        #check the password - notice password hash function
        elif not check_password_hash(user.password_hash, password): # takes the hash and password
            error = 'Incorrect password'
        if error is None:
            login_user(user)
            flash('You have successfully logged in!', 'success')
            return redirect(url_for('main.index'))
        else:
            flash(error, 'danger') 
    return render_template('user.html', form=login_form, heading='Login')

@authbp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out successfully', 'success')
    return redirect(url_for('main.index'))