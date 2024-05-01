from flask import Flask, request, jsonify
import mysql.connector
import re
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, verify_jwt_in_request
from pymysql import IntegrityError
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
from flask_mail import Mail, Message  # Import Flask-Mail
from werkzeug.utils import secure_filename
import os
from datetime import datetime
from flask_jwt_extended import jwt_required, get_jwt_identity

app = Flask(__name__)
CORS(app)

# MySQL Configuration
MYSQL_HOST = 'localhost'
MYSQL_USER = 'root'
MYSQL_PASSWORD = 'anuabhi2800'
MYSQL_DB = 'job'
app.config['MYSQL_DATABASE_PORT'] = 3306
app.config['MYSQL_POOL_RECYCLE'] = 3600

# Flask JWT Configuration
app.config['JWT_SECRET_KEY'] = 'job_key'
jwt = JWTManager(app)

# File Upload Configuration
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'doc', 'docx'}
UPLOAD_FOLDER = 'C:/jobapplication/backend/files'  # Specify the upload folder path
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # Maximum file size (16MB)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# Email Configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  # Update with your SMTP server address
app.config['MAIL_PORT'] = 587  # Update with your SMTP server port
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'cheeraganesh1995@gmail.com'  # Update with your email address
app.config['MAIL_PASSWORD'] = 'yajy sueh ldfa yovv'  # Update with your email password
app.config['MAIL_DEFAULT_SENDER'] = 'your-email@example.com'

mail = Mail(app)

# Password regex pattern
PASSWORD_REGEX = re.compile(r'^(?=.*[0-9])(?=.*[!@#$%^&*])(?=.*[a-zA-Z]).{8,}$')


# Function to check if file extension is allowed
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# Function to generate a unique filename
def generate_unique_filename(filename):
    return secure_filename(filename)


# Function to establish database connection
def db_connection():
    try:
        connection = mysql.connector.connect(
            host=MYSQL_HOST,
            user=MYSQL_USER,
            password=MYSQL_PASSWORD,
            database=MYSQL_DB
        )
        print('Database connection established')
        return connection
    except Exception as e:
        print(f'Database connection failed: {e}')


# Function to generate a token
def generate_token():
    import secrets
    return secrets.token_urlsafe(16)


def send_password_reset_email(email, token):
    reset_link = f'http://localhost:3000/upassword?token={token}'
    msg = Message('Password Reset Request', recipients=[email])
    msg.body = f'Hello,\n\nTo reset your password, please click on the following link: {reset_link}'
    try:
        mail.send(msg)
    except Exception as e:
        app.logger.error(f'Error sending password reset email to {email}: {e}')



# Flask route for user signup
@app.route('/signup', methods=['POST'])
def signup():
    try:
        data = request.json
        firstname = data['firstname']
        lastname = data['lastname']
        email = data['email']
        phone_number = data['phone_number']
        password = data['password']
        user_role = 'user'

        if not PASSWORD_REGEX.match(password):
            return jsonify({'error': 'Password must contain at least one symbol, one number, and be at least 8 characters long'}), 400

        hashed_password = generate_password_hash(password)

        connection = db_connection()

        if connection:
            cursor = connection.cursor()
            query = "INSERT INTO user (firstname, lastname, email, phone_number, user_role, password) VALUES (%s, %s, %s, %s, %s, %s)"
            cursor.execute(query, (firstname, lastname, email, phone_number, user_role, hashed_password))
            connection.commit()
            cursor.close()
            connection.close()
            return jsonify({'message': 'User signup successful'}), 201
        else:
            return jsonify({'error': 'Database connection failed'}), 500

    except IntegrityError as e:
        if "Duplicate entry" in str(e):
            return jsonify({'error': f'Duplicate entry for email {email}'}), 400
        else:
            return jsonify({'error': f'Signup problem: {e}'}), 500
    except Exception as e:
        return jsonify({'error': f'Signup problem: {e}'}), 500


# Flask route for user login
@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.json
        email = data['email']
        password = data['password']
        connection = db_connection()
        if connection:
            cursor = connection.cursor()
            query = "SELECT * FROM user WHERE email = %s"
            cursor.execute(query, (email,))
            user = cursor.fetchone()
            cursor.close()
            connection.close()
            if user:
                user_id = user[0]
                hashed_password_db = user[6]
                user_role = user[5]
                if check_password_hash(hashed_password_db, password):
                    access_token = create_access_token(identity=user_id)
                    connection = db_connection()
                    if connection:
                        cursor = connection.cursor()
                        update_query = "UPDATE user SET token = %s WHERE email = %s"
                        cursor.execute(update_query, (access_token, email))
                        connection.commit()
                        cursor.close()
                        connection.close()
                    return jsonify(access_token=access_token, user_role=user_role), 200
                else:
                    return jsonify({'message': 'Login problem'}), 500
            else:
                return jsonify({'Problem with database connection'}), 400
    except Exception as e:
        return jsonify({'message': f'Login problem: {e}'}), 500


# Flask route for retrieving user profile
@app.route('/profile', methods=['GET'])
@jwt_required()
def profile():
    try:
        user_id = get_jwt_identity()
        connection = db_connection()
        if connection:
            cursor = connection.cursor()
            query = "SELECT * FROM user WHERE id = %s"
            cursor.execute(query, (user_id,))
            userDetails = cursor.fetchall()
            cursor.close()
            connection.close()
            user = []
            for i in userDetails:
                user_detail = {
                    'id': i[0],
                    'firstname': i[1],
                    'lastname': i[2],
                    'email': i[3],
                    'phone_number': i[4],
                    'user_role': i[5],
                    'password': i[6],
                    'token': i[7]
                }
                user.append(user_detail)
            return jsonify(user), 201
        else:
            return jsonify({'Problem with database connection'}), 400
    except Exception as e:
        return jsonify({'message': f'get Profile error: {e}'}), 500

@app.route('/forgot-password', methods=['POST'])
def forgot_password():
    try:
        data = request.json
        email = data.get('email')

        # Check if the email is provided
        if not email:
            return jsonify({'error': 'Email is required'}), 400

        # Check if the email exists in the database
        connection = db_connection()
        if not connection:
            return jsonify({'error': 'Database connection failed'}), 500

        cursor = connection.cursor()
        query = "SELECT * FROM user WHERE email = %s"
        cursor.execute(query, (email,))
        user = cursor.fetchone()
        cursor.close()

        if not user:
            return jsonify({'error': 'Email not found'}), 404

        # Generate a unique token
        token = generate_token()

        # Store the token in the database for this user
        cursor = connection.cursor()
        update_query = "UPDATE user SET token = %s WHERE email = %s"
        cursor.execute(update_query, (token, email))
        connection.commit()
        cursor.close()

        # Send the password reset email
        send_password_reset_email(email, token)

        return jsonify({'message': 'Password reset email sent successfully'}), 200
    except Exception as e:
        app.logger.error(f'Forgot password error: {e}')
        return jsonify({'error': 'Internal Server Error'}), 500

# Update the reset password route to verify token and update password
@app.route('/reset-password', methods=['POST'])
def reset_password():
    try:
        data = request.json
        email = data.get('email')
        token = data.get('token')
        new_password = data.get('password')

        # Verify if email, token, and new_password are provided
        if not email or not token or not new_password:
            return jsonify({'error': 'Email, token, and new password are required'}), 400

        # Verify the token
        connection = db_connection()
        if not connection:
            return jsonify({'error': 'Database connection failed'}), 500

        cursor = connection.cursor()
        query = "SELECT token FROM user WHERE email = %s"
        cursor.execute(query, (email,))
        stored_token = cursor.fetchone()
        cursor.close()

        if not stored_token or stored_token[0] != token:
            return jsonify({'error': 'Invalid or expired token'}), 400

        # Update the password in the database
        hashed_password = generate_password_hash(new_password)
        cursor = connection.cursor()
        update_query = "UPDATE user SET password = %s, token = NULL WHERE email = %s"
        cursor.execute(update_query, (hashed_password, email))
        connection.commit()
        cursor.close()
        connection.close()

        return jsonify({'message': 'Password updated successfully'}), 200
    except Exception as e:
        app.logger.error(f'Reset password error: {e}')
        return jsonify({'error': 'Internal Server Error'}), 500

@app.route('/update-password', methods=['OPTIONS'])
def handle_options():
    return '', 200, {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        'Access-Control-Allow-Methods': 'POST',
    }

@app.route('/education',methods=['POST'])
@jwt_required()
def education():
    try:
        edu_user_id=get_jwt_identity()
        data=request.json
        institution_name=data['institution_name']
        degree=data['degree']
        field_of_study=data['field_of_study']
        description=data['description']
        start_date=data['start_date']
        end_date=data['end_date']
        connection=db_connection()
        if connection:
            cursor=connection.cursor()
            query="insert into education_details (edu_user_id,institution_name,degree,field_of_study,description,start_date,end_date) values (%s,%s,%s,%s,%s,%s,%s)"
            cursor.execute(query,(edu_user_id,institution_name,degree,field_of_study,description,start_date,end_date))
            connection.commit()
            cursor.close()
            connection.close()
            return jsonify({'Message':'education added successfully'}),201
        else:
            return jsonify({'Problem with database connection'}),500
    except Exception as e:
        return jsonify({'message':f'Adding education problem is: {e}'}),500

@app.route('/geteducation',methods=['GET'])
@jwt_required()
def get_education():
    try:
        get_user_id=get_jwt_identity()
        connection=db_connection()
        if connection:
            cursor=connection.cursor()
            query="select * from education_details where edu_user_id=%s"
            cursor.execute(query,(get_user_id,))
            education_details=cursor.fetchall()
            cursor.close()
            connection.close()
            education = []
            for edu in education_details:
                educations = {
                    'id': edu[0],
                    'edu_user_id': edu[1],
                    'institution_name': edu[2],
                    'degree': edu[3],
                    'field_of_study': edu[4],
                    'start_date': edu[5],
                    'end_date': edu[6],
                    'description': edu[6]
                }
                education.append(educations)
            return jsonify(education),201
        else:
            return jsonify({'Problem with database connection'}),500
    except Exception as e:
        return jsonify({'message':f'get eductaion problem is {e}'}),500

@app.route('/update_education/<int:edu_id>',methods=['PUT'])
@jwt_required()
def update_edu(edu_id):
    try:
        getuserid=get_jwt_identity()
        data=request.json
        connection=db_connection()
        if connection:
            cursor=connection.cursor()
            query=("update education_details set institution_name=%s,degree=%s,field_of_study=%s,description=%s,start_date=%s,end_date=%s where id=%s and edu_user_id=%s")
            cursor.execute(query,(data['institution_name'],data['degree'],data['field_of_study'],data['description'],data['start_date'],data['end_date'],edu_id,getuserid))
            connection.commit()
            cursor.close()
            connection.close()
            return jsonify({'message':'Update education successfully'}),201
        else:
            return jsonify({'Problem with database connection'}), 500
    except Exception as e:
        return jsonify({'message':f'Update education is failed :{e}'}),500

@app.route('/delete_education/<int:edu_id>',methods=['DELETE'])
@jwt_required()
def deleteeducation(edu_id):
    try:
        getuserid=get_jwt_identity()
        connection=db_connection()
        if connection:
            cursor=connection.cursor()
            query="delete from education_details where id=%s and edu_user_id=%s"
            cursor.execute(query,(edu_id,getuserid))
            connection.commit()
            cursor.close()
            connection.close()
            return jsonify({'message':'Education delete successfully'}),201
        else:
            return jsonify({'Problem with database connection'}),500
    except Exception as e:
        return jsonify({'message':f'Delete education details is {e}'})

@app.route('/experience',methods=['POST'])
@jwt_required()
def experiences():
    try:
        exp_user_id=get_jwt_identity()
        data=request.json
        company_name=data['company_name']
        position=data['position']
        exp_start_date=data['exp_start_date']
        exp_end_date=data['exp_end_date']
        exp_description=data['exp_description']
        connection=db_connection()
        if connection:
            cursor=connection.cursor()
            query="insert into job_experiences (exp_user_id,company_name,position,exp_start_date,exp_end_date,exp_description) values (%s,%s,%s,%s,%s,%s)"
            cursor.execute(query,(exp_user_id,company_name,position,exp_start_date,exp_end_date,exp_description))
            connection.commit()
            cursor.close()
            connection.close()
            return jsonify({'message':'Adding experience is successfully'}),201
        else:
            return jsonify({'Problem with database connection'}),500
    except Exception as e:
        return jsonify({'message':f'Adding experience is error {e}'}),500

@app.route('/get_experience',methods=['GET'])
@jwt_required()
def getExperience():
    try:
        getUserID=get_jwt_identity()
        connection=db_connection()
        if connection:
            cursor=connection.cursor()
            query=("select * from job_experiences where exp_user_id=%s")
            cursor.execute(query,(getUserID,))
            user_exp=cursor.fetchall()
            cursor.close()
            connection.close()
            experiences = []
            for exp in user_exp:
                experience = {
                    'id': exp[0],
                    'user_id': exp[1],
                    'company_name': exp[2],
                    'position': exp[3],
                    'exp_start_date': exp[4],
                    'exp_end_date': exp[5],
                    'exp_description': exp[6]
                }
                experiences.append(experience)
            return jsonify(experiences), 201
        else:
            return jsonify({'Problem with database connection'}),500
    except Exception as e:
        return jsonify({'message':f'Get experience error is:{e}'}),500

@app.route('/user_upd_exp/<int:exp_id>',methods=['PUT'])
@jwt_required()
def update_exp(exp_id):
    try:
        data=request.json
        getUserExperienceId=get_jwt_identity()
        connection=db_connection()
        if connection:
            cursor=connection.cursor()
            query="Update job_experiences set company_name=%s,position=%s,exp_start_date=%s,exp_end_date=%s,exp_description=%s where id=%s and exp_user_id=%s"
            cursor.execute(query,(data['company_name'],data['position'],data['exp_start_date'],data['exp_end_date'],data['exp_description'],exp_id,getUserExperienceId))
            connection.commit()
            cursor.close()
            connection.close()
            return jsonify({'message':'Update experience sucessfully'}),201
        else:
            return jsonify({'Problem with database connection'}),500
    except Exception as e:
        return jsonify({'message':f'Experiences Update error is: {e}'}),500

@app.route('/del_usr_exp/<int:exp_id>',methods=['DELETE'])
@jwt_required()
def exp_delete(exp_id):
    try:
        getuserExp=get_jwt_identity()
        connection=db_connection()
        if connection:
            cursor=connection.cursor()
            query="delete from job_experiences where id=%s and exp_user_id=%s"
            cursor.execute(query,(exp_id,getuserExp))
            connection.commit()
            cursor.close()
            connection.close()
            return jsonify({'message':'Experience Delete successfully'}),201
        else:
            return jsonify({'Problem with database connection'}),500
    except Exception as e:
        return jsonify({'message':f'Delete Experience erroe is :{e}'}),500

@app.route('/job_poistion',methods=['POST'])
@jwt_required()
def jobPosition():
    try:
        verify_jwt_in_request()
        getUser=get_jwt_identity()
        connection=db_connection()
        if connection:
            cursor=connection.cursor()
            query="select user_role from user where id=%s"
            cursor.execute(query,(getUser,))
            user_role=cursor.fetchone()[0]
            print(user_role)
            cursor.close()
            connection.close()

            if user_role!='recruiter':
                return jsonify({'message':'You dont have access to add job portal only recruiter'}),403
        data=request.json
        JobTitle=data.get('JobTitle')
        company_employees=data.get('company_employees')
        job_prefer_skills=data.get('job_prefer_skills')
        job_salary=data.get('job_salary')
        About_the_job=data.get('About_the_job')
        preferred_qualification=data.get('preferred_qualification')
        job_Responsibilities=data.get('job_Responsibilities')
        company_location=data.get('company_location')
        company_workplace=data.get('company_workplace')
        job_type=data.get('job_type')
        company_logo=data.get('company_logo')
        connections=db_connection()
        if connections:
            cursor=connections.cursor()
            query= """INSERT INTO job_production 
                       (JobTitle, company_employees, job_prefer_skills, job_salary, About_the_job, 
                        preferred_qualification, job_Responsibilities, company_location, company_workplace, 
                        job_type, company_logo, userid) 
                       VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"""
            cursor.execute(query,(JobTitle,company_employees,job_prefer_skills,job_salary,About_the_job,preferred_qualification,job_Responsibilities,company_location,company_workplace,job_type,company_logo,getUser))
            connections.commit()
            cursor.close()
            connections.close()
            return jsonify({'message':'Job added successfully'}),201
        else:
            return jsonify({'Problem with database connection'}),500
    except Exception as e:
        return jsonify({'message':f'JobPoistion error is: {e}'}),500

@app.route('/get_job_applications',methods=['GET'])
@jwt_required()
def getJobApplication():
    try:
        verify_jwt_in_request()
        getUser=get_jwt_identity()
        connection=db_connection()
        if connection:
            cursor=connection.cursor()
            query="select user_role from user where id=%s"
            cursor.execute(query,(getUser,))
            user_role=cursor.fetchone()[0]
            cursor.close()
            connection.close()
            if user_role!='recruiter':
                return jsonify({'message':'You dont get any data because your not recruiter'}),403
        connections=db_connection()
        if connections:
            cursor=connections.cursor()
            query="select * from job_production where userid=%s"
            cursor.execute(query,(getUser,))
            get_job_details=cursor.fetchall()
            cursor.close()
            connections.close()
            jobApplications=[]
            for i in get_job_details:
                get_jobs={
                    'id':i[0],
                    'JobTitle':i[1],
                    'company_employees':i[2],
                    'job_prefer_skills':i[3],
                    'job_salary':i[4],
                    'About_the_job':i[5],
                    'preferred_qualification':i[6],
                    'job_Responsibilities':i[7],
                    'company_location':i[8],
                    'company_workplace':i[9],
                    'job_type':i[10],
                    'company_logo':i[11],
                    'userid':i[12]
                }
                jobApplications.append(get_jobs)
            return jsonify(jobApplications),201
        else:
            return jsonify({'Database connection is lose'}),500
    except Exception as e:
        return jsonify({'message':f'get job application error is :{e}'}),500

@app.route('/update_jobPosting/<job_id>',methods=['PUT'])
@jwt_required()
def updateJobPosting(job_id):
    try:
        data=request.json
        verify_jwt_in_request()
        getUser=get_jwt_identity()
        connection=db_connection()
        if connection:
            cursor=connection.cursor()
            query="select user_role from user where id=%s"
            cursor.execute(query,(getUser,))
            user_role=cursor.fetchone()[0]
            cursor.close()
            connection.close()
            if user_role!='recruiter':
                return jsonify({'message':'You dont have access to update because your not recruiter'}),403
        connections=db_connection()
        if connections:
            cursor=connections.cursor()
            query="update job_production set JobTitle=%s,company_employees=%s,job_prefer_skills=%s,job_salary=%s,About_the_job=%s,preferred_qualification=%s,job_Responsibilities=%s,company_location=%s,company_workplace=%s,job_type=%s,company_logo=%s where id=%s and userid=%s"
            cursor.execute(query,(data['JobTitle'],data['company_employees'],data['job_prefer_skills'],data['job_salary'],data['About_the_job'],data['preferred_qualification'],data['job_Responsibilities'],data['company_location'],data['company_workplace'],data['job_type'],data['company_logo'],job_id,getUser))
            connections.commit()
            cursor.close()
            connections.close()
            return jsonify({'message':'Update job productions successfully'}),201
        else:
            return jsonify({'Database connection is lose'}),500
    except Exception as e:
        return jsonify({'message':f'Job update error is:{e}'}),500

@app.route('/delete_jobPosting/<job_id>',methods=['DELETE'])
def deleteJobPosting(job_id):
    try:
        verify_jwt_in_request()
        getUser=get_jwt_identity()
        connection=db_connection()
        if connection:
            cursor=connection.cursor()
            query="select user_role from user where id=%s"
            cursor.execute(query,(getUser,))
            user_role=cursor.fetchone()[0]
            cursor.close()
            connection.close()
            if user_role!='recruiter':
                return jsonify({'message':"You can't delete jobapplication"}),403
        connections=db_connection()
        if connections:
            cursor=connections.cursor()
            query="delete from job_production where id=%s and userid=%s"
            cursor.execute(query,(job_id,getUser))
            connections.commit()
            cursor.close()
            connections.close()
            return jsonify({'message':'Job Production deleted successfully'}),201
        else:
            return jsonify({'Database connection is lose'}),500
    except Exception as e:
        return jsonify({'message':f'Delete job production error is:{e}'}),500

@app.route('/update_user_role/<int:user_id>', methods=['PUT'])
@jwt_required()
def update_user_role(user_id):
    try:
        verify_jwt_in_request()
        current_user_id = get_jwt_identity()
        data = request.json
        new_role = data.get('new_role')

        connection = db_connection()
        if connection:
            cursor = connection.cursor()
            # Check if the current user is an admin
            admin_query = "SELECT user_role FROM user WHERE id = %s"
            cursor.execute(admin_query, (current_user_id,))
            current_user_role = cursor.fetchone()[0]
            if current_user_role != 'admin':
                return jsonify({'message': "You don't have permission to update user roles"}), 403

            # Update the user role
            update_query = "UPDATE user SET user_role = %s WHERE id = %s"
            cursor.execute(update_query, (new_role, user_id))
            connection.commit()
            cursor.close()
            connection.close()
            return jsonify({'message': 'User role updated successfully'}), 201
        else:
            return jsonify({'Problem with database connection'}), 500
    except Exception as e:
        return jsonify({'message': f'Update user role error: {e}'}), 500

@app.route('/get_all_user',methods=['GET'])
@jwt_required()
def getAllUser():
    try:
        verify_jwt_in_request()
        getUSer=get_jwt_identity()
        connection=db_connection()
        if connection:
            cursor=connection.cursor()
            query="select user_role from user where id=%s"
            cursor.execute(query,(getUSer,))
            user_role=cursor.fetchone()[0]
            cursor.close()
            connection.close()
            if user_role!='admin':
                return jsonify({'message':'Only admin will get the user data'}),403
        connections=db_connection()
        if connections:
            cursor=connections.cursor()
            query="select * from user"
            cursor.execute(query)
            get_all=cursor.fetchall()
            connections.commit()
            cursor.close()
            connections.close()
            users=[]
            for i in get_all:
                getusers={
                    'id':i[0],
                    'firstname':i[1],
                    'lastname':i[2],
                    'email':i[3],
                    'phone_number':i[4],
                    'user_role':i[5]
                }
                users.append(getusers)
            return jsonify(users),201
        else:
            return jsonify({'Problem with database connection'}), 500
    except Exception as e:
        return jsonify({'message':f'Get user Data error is:{e}'}),500

@app.route('/getalljobs',methods=['GET'])
def getAllJobs():
    try:
        connection=db_connection()
        if connection:
            cursor=connection.cursor()
            query="select * from job_production"
            cursor.execute(query)
            getalljobs=cursor.fetchall()
            connection.commit()
            cursor.close()
            connection.close()
            getall=[]
            for i in getalljobs:
                getA={
                        "id":i[0],
                        "JobTitle":i[1],
                        "company_employees":i[2],
                        "job_prefer_skills":i[3],
                        "job_salary":i[4],
                        "About_the_job": i[5],
                        "preferred_qualification":i[6],
                        "job_Responsibilities":i[7],
                        "company_location":i[8],
                        "company_workplace":i[9],
                        "job_type":i[10],
                        "company_logo":i[11]
                }
                getall.append(getA)
            return jsonify(getall),201
        else:
            return jsonify({'Problem with database connection'}), 500
    except Exception as e:
        return jsonify({'message':f'getalljobs error is:{e}'}),500

@app.route('/save_job', methods=['POST'])
@jwt_required()
def save_job():
    try:
        current_user_id = get_jwt_identity()
        data = request.json
        user_id = data['user_id']

        # Check if the current user is the same as the user_id in the request
        if current_user_id != user_id:
            return jsonify({"message": "Unauthorized"}), 401

        job_id = data['job_id']

        connection = db_connection()
        cursor = connection.cursor()

        # Save job for user
        query = "INSERT INTO saved_jobs (user_id, job_id) VALUES (%s, %s)"
        cursor.execute(query, (user_id, job_id))
        connection.commit()

        cursor.close()
        connection.close()

        return jsonify({"message": "Job saved successfully"}), 201

    except Exception as e:
        return jsonify({"message": f"Error saving job: {e}"}), 500

@app.route('/get_saved_jobs', methods=['GET'])
@jwt_required()
def get_saved_jobs():
    try:
        current_user_id = get_jwt_identity()

        # Fetch saved jobs for the current user
        connection = db_connection()
        cursor = connection.cursor()

        query = """
            SELECT j.id, j.JobTitle, j.company_employees, j.job_salary, j.About_the_job, j.company_location, j.company_workplace, j.job_type, j.company_logo
            FROM saved_jobs s
            JOIN job_production j ON s.job_id = j.id
            WHERE s.user_id = %s
        """
        cursor.execute(query, (current_user_id,))
        saved_jobs = cursor.fetchall()

        cursor.close()
        connection.close()

        # Construct response
        jobs_list = []
        for job in saved_jobs:
            job_dict = {
                "id": job[0],
                "JobTitle": job[1],
                "company_employees": job[2],
                "job_salary": str(job[3]),
                "About_the_job": job[4],
                "company_location": job[5],
                "company_workplace": job[6],
                "job_type": job[7],
                "company_logo": job[8]
            }
            jobs_list.append(job_dict)

        return jsonify(jobs_list), 200

    except Exception as e:
        return jsonify({"message": f"Error getting saved jobs: {e}"}), 500

@app.route('/remove_saved_job', methods=['DELETE'])
def remove_saved_job():
    try:
        data = request.json
        user_id = data['user_id']
        job_id = data['job_id']

        connection = db_connection()
        cursor = connection.cursor()

        query = "DELETE FROM saved_jobs WHERE user_id = %s AND job_id = %s"
        cursor.execute(query, (user_id, job_id))
        connection.commit()

        cursor.close()
        connection.close()

        return jsonify({"message": "Job removed successfully"}), 200

    except Exception as e:
        return jsonify({"message": f"Error removing job: {e}"}), 500

import os

# Specify the upload folder path relative to the current working directory
@app.route('/apply_job', methods=['POST'])
@jwt_required()
def apply_job():
    try:
        data = request.form  # Form data contains text fields
        user_id = get_jwt_identity()
        job_id = data.get('job_id')
        application_text = data.get('application_text')
        upload_resume = request.files['file']  # Retrieve the resume file
        status = ''  # Default status to empty string

        # Check if file is uploaded
        if upload_resume.filename == '':
            return jsonify({'message': 'No file selected for uploading'}), 400

        # Check if the file extension is allowed
        if not allowed_file(upload_resume.filename):
            return jsonify({'message': 'Invalid file extension'}), 400

        filename = secure_filename(upload_resume.filename)
        upload_resume.save(os.path.join(UPLOAD_FOLDER, filename))  # Save the file to the specified upload folder

        connection = db_connection()
        cursor = connection.cursor()

        # Check if the user has already applied for this job
        check_query = "SELECT * FROM job_applications WHERE user_id = %s AND job_id = %s"
        cursor.execute(check_query, (user_id, job_id))
        if cursor.fetchone():
            return jsonify({'message': 'You have already applied for this job'}), 400

        # Insert the job application into the database
        insert_query = "INSERT INTO job_applications (user_id, job_id, application_text, status, upload_resume) VALUES (%s, %s, %s, %s, %s)"
        cursor.execute(insert_query, (user_id, job_id, application_text, status, filename))
        connection.commit()

        cursor.close()
        connection.close()

        return jsonify({'message': 'Job application submitted successfully'}), 201

    except Exception as e:
        # Log the error
        print(f"Error applying for job: {e}")
        return jsonify({'message': f'Error applying for job: {e}'}), 500

from flask import Flask, send_from_directory



@app.route('/job_applications', methods=['GET'])
@jwt_required()
def get_job_applications():
    try:
        # Establish database connection
        connection = db_connection()
        if connection:
            cursor = connection.cursor()

            # Execute SQL query to fetch job applications with user details
            query = """
                SELECT ja.id, ja.user_id, ja.job_id, ja.application_text, ja.status, ja.applied_at,upload_resume,
                       u.firstname, u.lastname, u.email, u.phone_number, u.user_role
                FROM job_applications ja
                JOIN user u ON ja.user_id = u.id
            """
            cursor.execute(query)
            job_applications = cursor.fetchall()

            # Close cursor and connection
            cursor.close()
            connection.close()

            # Construct response JSON
            response = []
            for application in job_applications:
                application_data = {
                    "id": application[0],
                    "user_id": application[1],
                    "job_id": application[2],
                    "application_text": application[3],
                    "status": application[4],
                    "applied_at": application[5].strftime('%Y-%m-%d %H:%M:%S'),  # Convert to string
                    "upload_resume":application[6],
                    "user": {
                        "firstname": application[7],
                        "lastname": application[8],
                        "email": application[9],
                        "phone_number": application[10],
                        "user_role": application[11]
                    }
                }
                print(application[6])
                response.append(application_data)

            return jsonify(response), 200

        else:
            return jsonify({"error": "Problem with database connection"}), 500

    except Exception as e:
        return jsonify({"error": f"Error retrieving job applications: {e}"}), 500

@app.route('/user_job_applications', methods=['GET'])
@jwt_required()
def user_job_applications():
    try:
        # Get the user identity from the JWT
        user_id = get_jwt_identity()

        # Connect to the database
        connection = db_connection()
        cursor = connection.cursor()

        # Fetch job applications for the user
        query = """
            SELECT 
                ja.id AS application_id, 
                jp.id AS job_id, 
                jp.JobTitle AS job_title, 
                jp.company_employees AS company_employees, 
                jp.job_salary AS job_salary, 
                jp.About_the_job AS job_description, 
                jp.company_location AS company_location, 
                jp.company_workplace AS company_workplace, 
                jp.job_type AS job_type, 
                jp.company_logo AS company_logo,
                ja.status AS application_status
            FROM job_applications ja
            JOIN job_production jp ON ja.job_id = jp.id
            WHERE ja.user_id = %s
        """
        cursor.execute(query, (user_id,))
        job_applications = cursor.fetchall()

        # Close database cursor and connection
        cursor.close()
        connection.close()

        # Construct response
        user_applications = []
        for application in job_applications:
            application_dict = {
                "application_id": application[0],
                "job_details": {
                    "job_id": application[1],
                    "job_title": application[2],
                    "company_employees": application[3],
                    "job_salary": application[4],
                    "job_description": application[5],
                    "company_location": application[6],
                    "company_workplace": application[7],
                    "job_type": application[8],
                    "company_logo": application[9]
                },
                "application_status": application[10]
            }
            user_applications.append(application_dict)

        return jsonify(user_applications), 200

    except Exception as e:
        return jsonify({"message": f"Error getting user job applications: {e}"}), 500

@app.route('/job_application/<int:application_id>', methods=['PUT'])
@jwt_required()
def update_job_application(application_id):
    try:
        data = request.json
        new_status = data.get('status')

        # Ensure only the status field is updated
        if not new_status:
            return jsonify({"message": "Status field is required for update"}), 400

        connection = db_connection()
        cursor = connection.cursor()

        # Check if the job application exists
        query = "SELECT * FROM job_applications WHERE id = %s"
        cursor.execute(query, (application_id,))
        application = cursor.fetchone()

        if not application:
            return jsonify({"message": "Job application not found"}), 404

        # Update the status of the job application
        update_query = "UPDATE job_applications SET status = %s WHERE id = %s"
        cursor.execute(update_query, (new_status, application_id))
        connection.commit()

        cursor.close()
        connection.close()

        return jsonify({"message": "Job application status updated successfully"}), 200

    except Exception as e:
        return jsonify({"message": f"Error updating job application status: {e}"}), 500

if __name__=='__main__':
    connection=db_connection()
    app.run(debug=True)