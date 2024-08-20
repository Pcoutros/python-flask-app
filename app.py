'''This program generates a simple website using Python Flask module.
The website contents are about my dog Barley with different pieces of
information to view. The site itself is comprised of 4 different pages
and two forms: register and login. The user cannot access the web pages
until they successfully login. There are 3 links to external wiki pages,
links to pictures, link to a video, a table with pictures in it,
and the website displays the current datetime.

The username cannot be duplicated or blank. The password must be at least
12 characters and contain at least one upper case, one lower case, one
number, and one special character (not including ':' as that is used as
the separater in the text file.)

MODIFIED: user can now change the password of their account once logged in.
The passwords are also checked against a common password file and will
reject any matches. There is also a logger added for failed login attempts.

Note: The VS Code tutorial was followed in creating this program and
therefore will contain many of the same features (because I liked their
functionalities not didn't feel the need to 're-invent the wheel'). For
example, the nav bar at the top is a great feature that I wanted to keep.

Run from terminal, change directory to the folder that this app.py is in,
enter, then flask run, enter

Name: Pete Coutros
Date: 04/23/2023
Modified: 04/30/2023
Modified 2: 05/07/2023
'''

# Imports
from datetime import datetime, date
import logging
from passlib.hash import sha256_crypt
from flask import Flask, render_template, request, url_for, redirect, flash, \
    session

# Create Flask object
app = Flask(__name__)
app.secret_key = 'onlyiknow'

''' Set up logger

This section used guidance from the 'Advanved Logging Tutorial' section of the
Logging HOWTO of docs.python.org'''
# Create logger instance
logger = logging.getLogger('Failed Login Attempt')
# Set lowest level of logger to WARNING
logger.setLevel(logging.WARNING)
# Create file handler with log name
handler = logging.FileHandler('failed_attempts.log')
# Create formatter
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s '
                              '- %(message)s')
# Add formatter to file handler
handler.setFormatter(formatter)
# Add file handler to logger
logger.addHandler(handler)


# Define a list of routes that require authentication
auth_required_routes = ['/menu/home', '/about/', '/contact/', '/menu/',
                        '/update']


# Define the required login function with before_request decorator
@app.before_request
def require_login():

    '''This function will check if the user is logged in before allowing access
    to certain routes.'''

    # If user not logged in, send back to start page
    if request.path in auth_required_routes and 'username' not in session:
        flash('You must be logged in to view this page', 'error')
        return redirect(url_for('start'))

    # PEP8 consistent return statement for a function
    return None


# Define date function
def todays_date():

    '''This function will get today's date using datetime import.

    This is to be used on each route as the datetime is displayed at the footer
    Input: None
    Output: datetime'''

    return datetime.now()


# Define Calculate age function
def calculate_age():

    '''This function will calculate the age of Barley using the current date.

    Her birthday is hardcoded in this function as April 5, 2017.
    Input: None
    Output: Integer'''

    # Get todays date
    today = date.today()

    # Set Barley's birthday
    bday = date(2017, 4, 5)

    # Calculate age
    age = today.year - bday.year - ((today.month, today.day) <
                                    (bday.month, bday.day))
    return age


# Define validate password function
def validate_password(password):

    '''This function validates the user password.

    The password must contain at least 12 characters and include at least one
    upper case character, one lower case, one number, and one special character
    excluding ':'. The password cannot be found in the CommonPassword.txt file.
    Input: password (string)
    Output: is_valid (boolean) and message (string)'''

    # Initialize variables
    is_valid = True
    special_characters = ['`', '~', '!', '@', '#', '$', '%', '^', '&', '*'
                          '(', ')', '-', '_', '+', '=', '[', ']', '{', '}'
                          '\\', '|', ';', '"', "'", '<', '>', ',', '.'
                          '?', '/']

    # Validate password and display different errors
    if len(password) < 12:
        is_valid = False
        flash('Password must be 12 or more characters in length.', 'error')
    elif not any(char.isupper() for char in password):
        is_valid = False
        flash('Password must contain an Upper Case character.', 'error')
    elif not any(char.islower() for char in password):
        is_valid = False
        flash('Password must contain an Lower Case character.', 'error')
    elif not any(char.isdigit() for char in password):
        is_valid = False
        flash('Password must contain a digit.', 'error')
    elif not any(char in special_characters for char in password):
        is_valid = False
        flash('Password must contain a special character', 'error')
    elif any(char == ':' for char in password):
        is_valid = False
        flash("Password cannot contain ':'", 'error')
    # If none of the above caused pwd to fail, check the file
    elif is_valid:

        # Read in common passwords file
        with open('CommonPassword.txt', 'r', encoding="utf-8") as file:

            common_pword = file.read().splitlines()

        # iterate through the passwords in the file and compare to user entry
        for pword in common_pword:
            if password == pword:       # If password in file, reject
                is_valid = False
                flash('Your password is found in CommonPasswords.txt', 'error')

    return is_valid


# Map start page aka login function
@app.route("/")
def start():

    '''This function will render the login page when the site is launched'''

    # Bring user to home page if logged in
    if 'username' in session:
        flash('You are already logged in', 'error')
        return redirect(url_for('home'))

    return render_template(
        "login.html",
        date=todays_date()
    )


# Map login function
@app.route("/login", methods=["GET", "POST"])
def login():

    '''This function will render the login page'''

    # Get IP address of user
    ip_address = request.remote_addr

    # Bring user to home page if logged in
    if 'username' in session:
        flash('You are already logged in', 'error')
        return redirect(url_for('home'))

    # Get input from html form
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']

        # Open file and append
        with open('passfile.txt', 'a+', encoding="utf-8") as file:

            # Set pointer to begining of file
            file.seek(0)

            # Read in file
            for line in file.readlines():

                # Separate the username and password and check against input
                user, pwd = line.strip().split(':')
                if ((username == user) and (sha256_crypt.verify(password,
                                                                pwd))):
                    # Set session['username'] and go to home page
                    session['username'] = username
                    flash('Login successful', 'success')
                    return redirect(url_for('home'))

        # If invalid credentials redisplay login with error message
        flash('Invalid Username or Password', 'error')
        logger.warning('Failed Login Attempt from %s', ip_address)
        return render_template(
            "login.html",
            date=todays_date()
        )

    # Bring to start when "/login" entered in address bar
    return redirect(url_for('start'))


# Map register funciton
@app.route("/register", methods=["GET", "POST"])
def register():

    '''This function will render the register page'''

    # Bring user to home page if logged in
    if 'username' in session:
        flash('You are already logged in', 'error')
        return redirect(url_for('home'))

    # Get input from html form
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']

        # Open file and append
        with open('passfile.txt', 'a+', encoding="utf-8") as file:

            # Set pointer to begining of file
            file.seek(0)

            # Read in usernames and passwords under users as list
            users = [line.strip().split(':') for line in file.readlines()]

            # Iterate through list of lists [[user, pwd],[user, pwd],...]
            for user in users:

                # Redisplay register page if username taken with error msg
                if user[0] == username:  # 0 index refers to username
                    flash('Username already taken', 'error')
                    return render_template(
                        "register.html",
                        date=todays_date()
                    )

                # Redisplay register page if username blank with error msg
                if username == '':
                    flash('Username cannot  be blank', 'error')
                    return render_template(
                        "register.html",
                        date=todays_date()
                    )

            # Set pointer to end of file
            file.seek(0, 2)

            # Call function to validate password
            is_valid = validate_password(password)

            # Redisplay register page if invalid pwd with error msg
            if not is_valid:
                return render_template(
                    "register.html",
                    date=todays_date()
                )

            # Hash the password
            hash_password = sha256_crypt.hash(password)

            # Add user name and hashed pwd to end of txt file, display login
            file.writelines(f'{username}:{hash_password}\n')
            flash('Account created!', 'success')
            return render_template(
                "login.html",
                date=todays_date()
            )

    # Bring user to register if '/register' entered in address bar
    return render_template(
        "register.html",
        date=todays_date(),
    )


# Map update funtion to /update URL
@app.route("/update", methods=["GET", "POST"])
def update():

    '''This function will render the update page but only after login.

    Used to change the password of a logged in user'''

    # If user logged in then show update page
    if 'username' in session:

        # Get input from html form
        if request.method == "POST":
            password = request.form['password']

            # Validate new password
            is_valid = validate_password(password)

            # If the password is valid open file
            if is_valid:

                # Open file in read, read in lines as users
                with open('passfile.txt', 'r', encoding="utf-8") as file:

                    users = file.readlines()

                # Create empty updated users list
                updated_users = []

                # Iterate through user in users and pull username/password
                for user in users:
                    username, pword = user.strip().split(':')

                    # If the username in session, change password
                    if username == session['username']:
                        user = f'{username}:{sha256_crypt.hash(password)}\n'

                    # Otherwise keep original password
                    else:
                        user = f'{username}:{pword}\n'

                    # Append users to updated users list
                    updated_users.append(user)

                # Open file in write
                with open('passfile.txt', 'w', encoding="utf-8") as file:

                    # Add the updated users list
                    file.writelines(updated_users)

                    # Flash user of successful update, bring to home page
                    flash('Password successfully updated!', 'success')
                    return redirect(url_for('home'))

            # If new password is invalid reload update page
            else:

                return render_template(
                    "update.html",
                    date=todays_date()
                )

        return render_template(
            'update.html',
            date=todays_date()
        )

    # If user not logged in, bring them to login page
    flash('Please login to view this page', 'error')
    return render_template(
        "login.html",
        date=todays_date()
    )


# Map home function to Root and /menu/home URL
@app.route("/menu/home")  # Used to return user to home page from menu options
def home():

    '''This function will render the home page'''

    # If user is logged in then show homepage
    if 'username' in session:
        return render_template(
            "home.html",
            age=calculate_age(),
            date=todays_date()
        )

    # If user not logged in, bring them to login page
    flash('Please login to view this page', 'error')
    return render_template(
        "login.html",
        date=todays_date()
    )


# Map about function to /about/ URL
@app.route("/about/")
def about():

    '''This function will render the about page'''

    # If user is logged in then show about page
    if 'username' in session:
        return render_template(
            "about.html",
            date=todays_date()
        )

    # If user not logged in, bring them to login page
    flash('Please login to view this page', 'error')
    return render_template(
        "login.html",
        date=todays_date()
    )


# Map contact function to /contact/ URL
@app.route("/contact/")
def contact():

    '''This function will render the contact page'''

    # If user is logged in then show contact page
    if 'username' in session:
        return render_template(
            "contact.html",
            date=todays_date()
        )

    # If user not logged in, bring them to login page
    flash('Please login to view this page', 'error')
    return render_template(
        "login.html",
        date=todays_date()
    )


# Map menu function to /menu/ URL
@app.route("/menu/")
def menu():

    '''This function will render the menu page'''

    # If user is logged in then show menu page
    if 'username' in session:
        return render_template(
            "menu.html",
            date=todays_date()
        )

    # If user not logged in, bring them to login page
    flash('Please login to view this page', 'error')
    return render_template(
        "login.html",
        date=todays_date()
    )


# Map logout function to /logout
@app.route("/logout")
def logout():

    '''This function will log the user out and bring to login page.'''

    # Bring user to login page if already logged out
    if 'username' not in session:
        flash('You must be logged in first to log out', 'error')
        return redirect(url_for('start'))

    # Remove username from session to logout
    session.pop('username', None)

    # Bring user to login page
    flash('You have successfully logged out', 'success')
    return redirect(url_for('start'))
