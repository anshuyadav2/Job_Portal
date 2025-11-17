from flask import Flask, render_template, request, redirect, session, flash, url_for
import mysql.connector
from mysql.connector import pooling
import bcrypt
import os
import re

app = Flask(__name__, template_folder="templates", static_folder="static")
# It's crucial to set a strong secret key for session security
app.secret_key = os.environ.get("FLASK_SECRET", "very-secret-key-for-job-portal-project")

# --- Connection pool for better performance ---
# IMPORTANT: Update these credentials with your actual MySQL setup
dbconfig = {
    "host": os.environ.get("DB_HOST", "localhost"),
    "user": os.environ.get("DB_USER", "root"),
    "password": os.environ.get("DB_PASS", "tiger"),
    "database": os.environ.get("DB_NAME", "job_portal"),
    "auth_plugin": "mysql_native_password",
    "port": int(os.environ.get("DB_PORT", 3306))
}
# Using a connection pool prevents creating a new connection for every request
try:
    cnxpool = pooling.MySQLConnectionPool(pool_name="jobpool", pool_size=5, **dbconfig)
except mysql.connector.Error as err:
    print(f"Database Connection Error: {err}")
    cnxpool = None

def get_db_connection():
    """Gets a connection from the pool or returns None if the pool is not initialized."""
    if cnxpool:
        return cnxpool.get_connection()
    return None

# ---------------- Helpers ----------------
def current_user():
    """Returns the current user's session data."""
    if "user_id" in session:
        return {"id": session["user_id"], "role": session.get("role"), "name": session.get("user_name")}
    return None

def login_required(role=None):
    """A decorator to ensure the user is logged in, optionally checking the role."""
    def decorator(f):
        def wrapper(*args, **kwargs):
            user = current_user()
            if not user:
                flash("You need to log in to access this page.", "warning")
                return redirect(url_for("login"))
            if role and user["role"] != role:
                flash(f"Access denied. Only {role.capitalize()}s can view this page.", "danger")
                return redirect(url_for("dashboard"))
            return f(*args, **kwargs)
        # Fix for flask's endpoint name collision
        wrapper.__name__ = f.__name__
        return wrapper
    return decorator


# ---------------- ROUTES ----------------
@app.route("/")
def home():
    """Renders the homepage."""
    return render_template("home.html", user=current_user())

@app.route("/register", methods=["GET", "POST"])
def register():
    """Handles user registration for both student and employer."""
    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]
        password = request.form["password"].encode('utf-8')
        role = request.form["role"] # 'student' or 'employer'

        # Basic form validation
        if not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            flash("Invalid email address!", "danger")
            return redirect(url_for("register"))
        if len(password.decode('utf-8')) < 6:
            flash("Password must be at least 6 characters.", "danger")
            return redirect(url_for("register"))

        conn = get_db_connection()
        if not conn:
            flash("Database connection error.", "danger")
            return redirect(url_for("register"))
            
        try:
            cursor = conn.cursor(dictionary=True)
            # Check if user already exists
            cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
            if cursor.fetchone():
                flash("Account already exists with this email!", "danger")
                return redirect(url_for("register"))

            # Hash the password
            hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())

            # Insert new user
            cursor.execute(
                "INSERT INTO users (name, email, password, role) VALUES (%s, %s, %s, %s)",
                (name, email, hashed_password, role)
            )
            conn.commit()
            
            flash("Registration successful! Please log in.", "success")
            return redirect(url_for("login"))

        except Exception as e:
            conn.rollback()
            flash(f"An unexpected error occurred during registration: {e}", "danger")
            return redirect(url_for("register"))
        finally:
            cursor.close()
            conn.close()

    return render_template("register.html", user=current_user())

@app.route("/login", methods=["GET", "POST"])
def login():
    """Handles user login."""
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"].encode('utf-8')

        conn = get_db_connection()
        if not conn:
            flash("Database connection error.", "danger")
            return redirect(url_for("login"))

        try:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT id, name, password, role FROM users WHERE email = %s", (email,))
            user = cursor.fetchone()
            
            if user:
                # Check password
                if bcrypt.checkpw(password, user["password"].encode('utf-8')):
                    # Successful login - set session variables
                    session["loggedin"] = True
                    session["user_id"] = user["id"]
                    session["role"] = user["role"]
                    session["user_name"] = user["name"]
                    
                    flash(f"Welcome, {user['name']}!", "success")
                    return redirect(url_for("dashboard"))
                else:
                    flash("Incorrect password.", "danger")
            else:
                flash("User not found with that email.", "danger")

        except Exception as e:
            flash(f"An unexpected error occurred during login: {e}", "danger")

        finally:
            cursor.close()
            conn.close()
            
    return render_template("login.html", user=current_user())

@app.route("/logout")
def logout():
    """Logs the user out by clearing the session."""
    session.pop("loggedin", None)
    session.pop("user_id", None)
    session.pop("role", None)
    session.pop("user_name", None)
    flash("You have been logged out.", "info")
    return redirect(url_for("home"))

@app.route("/dashboard")
@login_required()
def dashboard():
    """Redirects user to their specific dashboard based on role."""
    user = current_user()
    if user["role"] == "student":
        return render_template("dashboard_student.html", user=user)
    elif user["role"] == "employer":
        return render_template("dashboard_employer.html", user=user)
    else:
        flash("Unknown user role.", "danger")
        return redirect(url_for("logout"))

@app.route("/jobs")
def view_jobs():
    """Displays all jobs with search and filter functionality."""
    search_query = request.args.get("search", "")
    location_filter = request.args.get("location", "")
    
    conn = get_db_connection()
    if not conn:
        flash("Database connection error.", "danger")
        return render_template("jobs.html", user=current_user(), jobs=[])
        
    try:
        cursor = conn.cursor(dictionary=True)
        
        sql_query = "SELECT id, title, company, description, location, salary, posted_by FROM jobs WHERE 1=1"
        params = []
        
        if search_query:
            # Search by title OR company (case-insensitive)
            sql_query += " AND (title LIKE %s OR company LIKE %s)"
            search_param = f"%{search_query}%"
            params.extend([search_param, search_param])
        
        if location_filter:
            # Filter by location (case-insensitive)
            sql_query += " AND location LIKE %s"
            params.append(f"%{location_filter}%")
            
        sql_query += " ORDER BY created_at DESC"
        
        cursor.execute(sql_query, tuple(params))
        jobs = cursor.fetchall()

    except Exception as e:
        flash(f"An error occurred while fetching jobs: {e}", "danger")
        jobs = []
        
    finally:
        cursor.close()
        conn.close()
        
    return render_template("jobs.html", 
                           user=current_user(), 
                           jobs=jobs, 
                           search_query=search_query, 
                           location_filter=location_filter)

@app.route("/job/<int:job_id>", methods=["GET"])
def job_detail(job_id):
    """Displays the detail page for a single job."""
    conn = get_db_connection()
    if not conn:
        flash("Database connection error.", "danger")
        return redirect(url_for("view_jobs"))
        
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT id, title, company, description, location, salary FROM jobs WHERE id = %s", (job_id,))
        job = cursor.fetchone()
        
        if not job:
            flash("Job not found.", "warning")
            return redirect(url_for("view_jobs"))

        user = current_user()
        has_applied = False
        if user and user['role'] == 'student':
            # Check if student has already applied
            cursor.execute("SELECT id FROM applications WHERE job_id = %s AND user_id = %s", (job_id, user['id']))
            if cursor.fetchone():
                has_applied = True
                
    except Exception as e:
        flash(f"An error occurred: {e}", "danger")
        return redirect(url_for("view_jobs"))
        
    finally:
        cursor.close()
        conn.close()
        
    return render_template("job_detail.html", job=job, user=current_user(), has_applied=has_applied)

@app.route("/apply/<int:job_id>", methods=["GET", "POST"])
@login_required(role="student")
def apply_job(job_id):
    """Handles the job application process for a student."""
    user = current_user()
    conn = get_db_connection()
    if not conn:
        flash("Database connection error.", "danger")
        return redirect(url_for("job_detail", job_id=job_id))
        
    try:
        cursor = conn.cursor(dictionary=True)
        # 1. Fetch job details
        cursor.execute("SELECT id, title, company FROM jobs WHERE id = %s", (job_id,))
        job = cursor.fetchone()
        
        if not job:
            flash("Job not found.", "warning")
            return redirect(url_for("view_jobs"))
            
        # 2. Check if already applied
        cursor.execute("SELECT id FROM applications WHERE job_id = %s AND user_id = %s", (job_id, user['id']))
        if cursor.fetchone():
            flash("You have already applied for this job.", "info")
            return redirect(url_for("job_detail", job_id=job_id))

        if request.method == "POST":
            resume_link = request.form["resume"]
            
            # 3. Insert application
            cursor.execute(
                "INSERT INTO applications (job_id, user_id, resume) VALUES (%s, %s, %s)",
                (job_id, user["id"], resume_link)
            )
            conn.commit()
            
            flash(f"Successfully applied for {job['title']} at {job['company']}!", "success")
            return redirect(url_for("my_applications"))

        # GET request: render the application form
        return render_template("apply.html", job=job, user=user)

    except Exception as e:
        conn.rollback()
        flash(f"An error occurred during application: {e}", "danger")
        return redirect(url_for("job_detail", job_id=job_id))
        
    finally:
        cursor.close()
        conn.close()


@app.route("/post_job", methods=["GET", "POST"])
@login_required(role="employer")
def post_job():
    """Allows an employer to post a new job."""
    user = current_user()
    if request.method == "POST":
        title = request.form["title"]
        company = request.form["company"]
        description = request.form["description"]
        location = request.form["location"]
        salary = request.form["salary"]
        
        conn = get_db_connection()
        if not conn:
            flash("Database connection error.", "danger")
            return redirect(url_for("post_job"))
            
        try:
            cursor = conn.cursor(dictionary=True)
            cursor.execute(
                "INSERT INTO jobs (title, company, description, location, salary, posted_by) VALUES (%s, %s, %s, %s, %s, %s)",
                (title, company, description, location, salary, user["id"])
            )
            conn.commit()
            flash("Job posted successfully!", "success")
            return redirect(url_for("dashboard"))
            
        except Exception as e:
            conn.rollback()
            flash(f"An error occurred while posting job: {e}", "danger")
            
        finally:
            cursor.close()
            conn.close()
            
    return render_template("post_job.html", user=user)

@app.route("/view_applicants")
@login_required(role="employer")
def view_applicants():
    """Allows an employer to view all applications for their posted jobs."""
    user = current_user()
    conn = get_db_connection()
    if not conn:
        flash("Database connection error.", "danger")
        return render_template("view_applicants.html", applicants=[], user=user)

    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT 
                a.id, a.applied_at, a.resume, 
                u.name AS candidate_name, u.email AS candidate_email, 
                j.title
            FROM applications a
            JOIN users u ON a.user_id = u.id
            JOIN jobs j ON a.job_id = j.id
            WHERE j.posted_by = %s
            ORDER BY a.applied_at DESC
        """, (user["id"],))
        applicants = cursor.fetchall()
        
    except Exception as e:
        flash(f"An error occurred while fetching applicants: {e}", "danger")
        applicants = []
        
    finally:
        cursor.close()
        conn.close()
        
    return render_template("view_applicants.html", applicants=applicants, user=user)

@app.route("/my_applications")
def my_applications():
    user = current_user()
    if not user or user["role"] != "student":
        flash("Only students can view applications.", "warning")
        return redirect(url_for("login"))
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT j.id AS job_id, j.title, j.company, j.location, a.applied_at, a.resume
        FROM applications a
        JOIN jobs j ON a.job_id = j.id
        WHERE a.user_id = %s
        ORDER BY a.applied_at DESC
    """, (user["id"],))
    apps = cursor.fetchall()
    cursor.close()
    conn.close()
    return render_template("my_applications.html", apps=apps, user=user)

if __name__ == "__main__":
    # Ensure you set debug=False in a production environment
    app.run(debug=True)