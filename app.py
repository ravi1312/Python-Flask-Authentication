from myproject import app,db
from flask import render_template, redirect, request, url_for, flash,abort
from flask_login import login_user,login_required,logout_user
from myproject.models import User
from myproject.forms import LoginForm, RegistrationForm
from werkzeug.security import generate_password_hash, check_password_hash


@app.route('/')
def home():
    return render_template('base.html')


@app.route('/home')
@login_required
def welcome_user():
    return render_template('home.html')


@app.route('/base')
def base():
    return render_template('base.html')

@app.route('/welcome')
def welcome():
    return render_template('welcome.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You logged out!')
    return redirect(url_for('base'))

@app.route('/cse')
def cse():
    return render_template('cse.html')

@app.route('/csse')
def csse():
    return render_template('csse.html')

@app.route('/civil')
def civil():
    return render_template('civil.html')

@app.route('/ece')
def ece():
    return render_template('ece.html')

@app.route('/eee')
def eee():
    return render_template('eee.html')

@app.route('/eie')
def eie():
    return render_template('eie.html')

@app.route('/mech')
def mech():
    return render_template('mech.html')
@app.route('/mca')
def mca():
    return render_template('mca.html')
@app.route('/cs')
def cs():
    return render_template('cs.html')
@app.route('/eps')
def eps():
    return render_template('eps.html')
@app.route('/decs')
def decs():
    return render_template('decs.html')
@app.route('/comm.sys')
def comm():
    return render_template('comm.html')
@app.route('/cn&is')
def cn_is():
    return render_template('cn_is.html')
@app.route('/vlsi')
def vlsi():
    return render_template('vnsi.html')
@app.route('/se')
def si():
    return render_template('si.html')
@app.route('/ped')
def ped():
    return render_template('ped.html')
@app.route('/dcme')
def dcme():
    return render_template('dcme.html')
@app.route('/deee')
def deee():
    return render_template('deee.html')
@app.route('/dece')
def dece():
    return render_template('dece.html')
@app.route('/dce')
def dce():
    return render_template('dce.html')
@app.route('/dme')
def dme():
    return  render_template('dme.html')






@app.route('/login', methods=['GET', 'POST'])
def login():

    form = LoginForm()
    if form.validate_on_submit():
        # Grab the user from our User Models table
        user = User.query.filter_by(email=form.email.data).first()

        # Check that the user was supplied and the password is right
        # The verify_password method comes from the User object
        # https://stackoverflow.com/questions/2209755/python-operation-vs-is-not

        if user.check_password(form.password.data) and user is not None:
            #Log in the user

            login_user(user)
            flash('Logged in successfully.')

            # If a user was trying to visit a page that requires a login
            # flask saves that URL as 'next'.
            next = request.args.get('next')

            # So let's now check if that next exists, otherwise we'll go to
            # the welcome page.
            if next == None or not next[0]=='/':
                next = url_for('welcome_user')

            return redirect(next)
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()

    if form.validate_on_submit():
        user = User(email=form.email.data,
                    username=form.username.data,
                    password=form.password.data)

        db.session.add(user)
        db.session.commit()
        flash('Thanks for registering! Now you can login!')
        return redirect(url_for('welcome'))
    return render_template('registration.html', form=form)

if __name__ == '__main__':
    app.run(debug=True)
