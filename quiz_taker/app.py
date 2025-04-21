from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Initialize database
def init_db():
    conn = sqlite3.connect("database.db")
    c = conn.cursor()

    # Create Users Table (Adding is_blocked Column)
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY,
                    email TEXT UNIQUE,
                    password TEXT,
                    full_name TEXT,
                    qualification TEXT,
                    dob TEXT,
                    is_admin INTEGER DEFAULT 0,
                    is_blocked INTEGER DEFAULT 0)''')  # ✅ New column to track block status

    # Predefined Admin
    c.execute("SELECT * FROM users WHERE is_admin = 1")
    if not c.fetchone():
        admin_password = generate_password_hash('admin123')
        c.execute("INSERT INTO users (email, password, full_name, is_admin) VALUES (?, ?, ?, ?)", 
                  ('admin@example.com', admin_password, 'Quiz Master', 1))

    # Subjects Table
    c.execute('''CREATE TABLE IF NOT EXISTS subjects (
                    id INTEGER PRIMARY KEY,
                    name TEXT UNIQUE,
                    description TEXT)''')

    # Chapters Table
    c.execute('''CREATE TABLE IF NOT EXISTS chapters (
                    id INTEGER PRIMARY KEY,
                    subject_id INTEGER,
                    name TEXT,
                    description TEXT,
                    FOREIGN KEY(subject_id) REFERENCES subjects(id))''')

    # Quizzes Table
    c.execute('''CREATE TABLE IF NOT EXISTS quizzes (
                    id INTEGER PRIMARY KEY,
                    chapter_id INTEGER,
                    date_of_quiz TEXT,
                    time_duration TEXT,
                    remarks TEXT,
                    FOREIGN KEY(chapter_id) REFERENCES chapters(id))''')

    # Questions Table
    c.execute('''CREATE TABLE IF NOT EXISTS questions (
                    id INTEGER PRIMARY KEY,
                    quiz_id INTEGER,
                    question_statement TEXT,
                    option1 TEXT,
                    option2 TEXT,
                    option3 TEXT,
                    option4 TEXT,
                    correct_option INTEGER,
                    FOREIGN KEY(quiz_id) REFERENCES quizzes(id))''')

    # Scores Table
    c.execute('''CREATE TABLE IF NOT EXISTS scores (
                    id INTEGER PRIMARY KEY,
                    quiz_id INTEGER,
                    user_id INTEGER,
                    time_stamp TEXT,
                    total_scored INTEGER,
                    FOREIGN KEY(quiz_id) REFERENCES quizzes(id),
                    FOREIGN KEY(user_id) REFERENCES users(id))''')

    conn.commit()
    conn.close()

init_db()
def get_user_quiz_history(user_id):
    """Fetch quiz history for a specific user from the 'scores' table."""
    connection = sqlite3.connect('database.db')
    cursor = connection.cursor()

    cursor.execute("""
        SELECT scores.quiz_id, subjects.name, scores.time_stamp, scores.total_scored
        FROM scores
        JOIN quizzes ON scores.quiz_id = quizzes.id
        JOIN chapters ON quizzes.chapter_id = chapters.id
        JOIN subjects ON chapters.subject_id = subjects.id
        WHERE scores.user_id = ?
        """, (user_id,))

    quizzes = cursor.fetchall()
    connection.close()

    # Convert list of tuples into a list of dictionaries
    quiz_data = []
    for quiz in quizzes:
        quiz_data.append({
            'quiz_id': quiz[0],
            'subject': quiz[1],
            'date': quiz[2],
            'score': quiz[3],
            'correct': quiz[3],  # Using total score as correct answers
            'incorrect': 10 - quiz[3]  # Assuming quizzes have 10 questions
        })

    return quiz_data

def is_last_month(date_string):
    """Check if a given date is within the last 30 days, handling date + time formats."""
    try:
        # Try parsing YYYY-MM-DD format first
        quiz_date = datetime.strptime(date_string, "%Y-%m-%d")
    except ValueError:
        # If it fails, try parsing YYYY-MM-DD HH:MM:SS format
        quiz_date = datetime.strptime(date_string, "%Y-%m-%d %H:%M:%S")

    thirty_days_ago = datetime.today() - timedelta(days=30)
    return quiz_date >= thirty_days_ago


@app.route('/summary')
def summary():
    user_id = session.get('user_id')  # Get logged-in user ID
    quiz_data = get_user_quiz_history(user_id)  # Fetch user-specific quiz attempts

    # Get quiz scores and dates (only for last month)
    scores = [quiz['score'] for quiz in quiz_data if is_last_month(quiz['date'])]
    dates = [quiz['date'] for quiz in quiz_data if is_last_month(quiz['date'])]

    # Get subject-wise performance
    subject_scores = {}
    correct_answers = 0
    incorrect_answers = 0

    for quiz in quiz_data:
        subject = quiz['subject']
        if is_last_month(quiz['date']):
            if subject not in subject_scores:
                subject_scores[subject] = []
            subject_scores[subject].append(quiz['score'])

            correct_answers += quiz['correct']
            incorrect_answers += quiz['incorrect']

    # Calculate averages per subject
    subjects = list(subject_scores.keys())
    avg_subject_scores = [sum(subject_scores[subj]) / len(subject_scores[subj]) for subj in subjects]

    return render_template('summary.html', 
                           scores=scores, 
                           dates=dates, 
                           subjects=subjects, 
                           subject_scores=avg_subject_scores, 
                           correct_answers=correct_answers,
                           incorrect_answers=incorrect_answers)

@app.route("/admin/add_quiz", methods=["POST"])
def add_quiz():
    if "user" in session and session.get("is_admin"):
        chapter_id = request.form["chapter_id"]
        date_of_quiz = request.form["date_of_quiz"]
        time_duration = request.form["time_duration"]
        remarks = request.form.get("remarks", "")  # Optional field

        conn = sqlite3.connect("database.db")
        c = conn.cursor()
        c.execute(
            "INSERT INTO quizzes (chapter_id, date_of_quiz, time_duration, remarks) VALUES (?, ?, ?, ?)",
            (chapter_id, date_of_quiz, time_duration, remarks),
        )
        conn.commit()
        conn.close()

        print("Quiz added successfully!")  # Debugging statement
        return redirect(url_for("admin_dashboard"))

    return redirect(url_for("login"))

@app.route("/admin/search")
def search():
    if "user" in session and session.get("is_admin"):
        query = request.args.get("query", "").strip().lower()

        conn = sqlite3.connect("database.db")
        c = conn.cursor()

        # Search Users
        c.execute("SELECT id, email, full_name FROM users WHERE full_name LIKE ? OR email LIKE ?", 
                  (f"%{query}%", f"%{query}%"))
        users = [{"id": row[0], "email": row[1], "full_name": row[2]} for row in c.fetchall()]

        # Search Subjects & Chapters Together
        c.execute("SELECT id, name, description FROM subjects WHERE name LIKE ? OR description LIKE ?", 
                  (f"%{query}%", f"%{query}%"))
        subjects = []
        for subject in c.fetchall():
            subject_id, subject_name, subject_desc = subject
            
            # Get chapters under this subject
            c.execute("SELECT id, name FROM chapters WHERE subject_id = ? AND name LIKE ?", 
                      (subject_id, f"%{query}%"))
            chapters = [{"id": row[0], "name": row[1]} for row in c.fetchall()]

            subjects.append({
                "id": subject_id,
                "name": subject_name,
                "description": subject_desc,
                "chapters": chapters  # Nested chapters inside each subject
            })

        # Search Quizzes
        c.execute("SELECT id, date_of_quiz, time_duration FROM quizzes WHERE date_of_quiz LIKE ?", 
                  (f"%{query}%",))
        quizzes = [{"id": row[0], "date_of_quiz": row[1], "time_duration": row[2]} for row in c.fetchall()]

        conn.close()

        return jsonify({"users": users, "subjects": subjects, "quizzes": quizzes})

    return jsonify({"error": "Unauthorized"}), 403

@app.route("/admin/add_question", methods=["POST"])
def add_question():
    if "user" in session and session.get("is_admin"):
        quiz_id = request.form["quiz_id"]
        question_statement = request.form["question_statement"]
        option1 = request.form["option1"]
        option2 = request.form["option2"]
        option3 = request.form["option3"]
        option4 = request.form["option4"]
        correct_option = request.form["correct_option"]

        conn = sqlite3.connect("database.db")
        c = conn.cursor()
        c.execute(
            "INSERT INTO questions (quiz_id, question_statement, option1, option2, option3, option4, correct_option) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (quiz_id, question_statement, option1, option2, option3, option4, correct_option),
        )
        conn.commit()
        conn.close()

        print("Question added successfully!")  # Debugging statement
        return redirect(url_for("admin_dashboard"))

    return redirect(url_for("login"))
@app.route("/")
def home():
    if "user_id" in session:  # ✅ Check for user_id instead of "user"
        user_id = session["user_id"]
        conn = sqlite3.connect("database.db")
        c = conn.cursor()

        # Fetch subjects and chapters
        c.execute("SELECT id, name, description FROM subjects")
        subjects = c.fetchall()

        subjects_with_chapters = []
        for subject in subjects:
            c.execute("SELECT id, name FROM chapters WHERE subject_id = ?", (subject[0],))
            chapters = c.fetchall()

            chapters_with_quizzes = []
            for chapter in chapters:
                c.execute("SELECT id, date_of_quiz, time_duration FROM quizzes WHERE chapter_id = ?", (chapter[0],))
                quizzes = c.fetchall()
                chapters_with_quizzes.append((chapter[0], chapter[1], quizzes))

            subjects_with_chapters.append((subject[0], subject[1], subject[2], chapters_with_quizzes))

        # Fetch user quiz history with both Chapter Name and Quiz ID
        c.execute("""
            SELECT quizzes.id, quizzes.date_of_quiz, scores.total_scored, chapters.name 
            FROM scores
            JOIN quizzes ON scores.quiz_id = quizzes.id
            JOIN chapters ON quizzes.chapter_id = chapters.id
            WHERE scores.user_id = ?
            ORDER BY scores.time_stamp DESC
        """, (user_id,))
        quiz_history = c.fetchall()

        conn.close()

        return render_template("home.html", user=session.get("user"), subjects=subjects_with_chapters, quiz_history=quiz_history)

    return redirect(url_for("login"))  # ✅ Redirect to login if not logged in



@app.route("/leaderboard")
def leaderboard():
    if "user" in session:
        conn = sqlite3.connect("database.db")
        c = conn.cursor()

        # Fetch total scores per user
        c.execute("""
            SELECT users.full_name, users.email, SUM(scores.total_scored) as total_score
            FROM scores
            JOIN users ON scores.user_id = users.id
            GROUP BY users.id
            ORDER BY total_score DESC
        """)
        leaderboard_data = c.fetchall()

        conn.close()
        return render_template("leaderboard.html", leaderboard=leaderboard_data, enumerate=enumerate)  # ✅ Pass enumerate

    return redirect(url_for("login"))

@app.route("/start_quiz", methods=["POST"])
def start_quiz():
    if "user" in session:
        quiz_id = request.form["quiz_id"]

        conn = sqlite3.connect("database.db")
        c = conn.cursor()

        # Fetch quiz details
        c.execute("SELECT id, date_of_quiz, time_duration FROM quizzes WHERE id = ?", (quiz_id,))
        quiz = c.fetchone()

        # Fetch all questions for the quiz
        c.execute("SELECT id, question_statement, option1, option2, option3, option4 FROM questions WHERE quiz_id = ?", (quiz_id,))
        questions = c.fetchall()

        conn.close()

        return render_template("quiz_page.html", quiz=quiz, questions=questions)
    
    return redirect(url_for("login"))

@app.route("/submit_quiz", methods=["POST"])
def submit_quiz():
    if "user" in session:
        user_id = session["user_id"]
        quiz_id = request.form["quiz_id"]
        total_score = 0

        conn = sqlite3.connect("database.db")
        c = conn.cursor()

        # Get all questions for the quiz
        c.execute("SELECT id, correct_option FROM questions WHERE quiz_id = ?", (quiz_id,))
        questions = c.fetchall()

        for question in questions:
            question_id = str(question[0])
            correct_answer = str(question[1])
            user_answer = request.form.get("answer_" + question_id)

            if user_answer and user_answer == correct_answer:
                total_score += 1  # Increase score for correct answers

        # Store quiz result in scores table
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        c.execute("INSERT INTO scores (quiz_id, user_id, time_stamp, total_scored) VALUES (?, ?, ?, ?)",
                  (quiz_id, user_id, timestamp, total_score))

        conn.commit()
        conn.close()

        return redirect(url_for("quiz_results", quiz_id=quiz_id, score=total_score))
    
    return redirect(url_for("login"))

@app.route("/quiz_results/<int:quiz_id>/<int:score>")
def quiz_results(quiz_id, score):
    if "user" in session:
        return render_template("quiz_results.html", score=score)
    
    return redirect(url_for("login"))

@app.route("/admin/dashboard", methods=["GET"])
def admin_dashboard():
    if "user" in session and session.get("is_admin"):
        conn = sqlite3.connect("database.db")
        c = conn.cursor()

        # Fetch all subjects
        c.execute("SELECT id, name, description FROM subjects")
        subjects = c.fetchall()

        subjects_with_chapters = []
        for subject in subjects:
            c.execute("SELECT id, name FROM chapters WHERE subject_id = ?", (subject[0],))
            chapters = c.fetchall()

            chapters_with_quizzes = []
            for chapter in chapters:
                c.execute("SELECT id, date_of_quiz, time_duration FROM quizzes WHERE chapter_id = ?", (chapter[0],))
                quizzes = c.fetchall()

                quizzes_with_questions = []
                for quiz in quizzes:
                    c.execute("SELECT id, question_statement, option1, option2, option3, option4, correct_option FROM questions WHERE quiz_id = ?", (quiz[0],))
                    questions = c.fetchall()

                    # Append quiz details along with its questions
                    quizzes_with_questions.append((quiz[0], quiz[1], quiz[2], questions))

                # Append chapter details along with its quizzes
                chapters_with_quizzes.append((chapter[0], chapter[1], quizzes_with_questions))

            # Append subject details along with its chapters
            subjects_with_chapters.append((subject[0], subject[1], subject[2], chapters_with_quizzes))

        # Fetch all users (excluding admin)
        c.execute("SELECT id, full_name, email, is_blocked FROM users WHERE is_admin = 0")
        users = c.fetchall()

        conn.close()
        return render_template("admin_dashboard.html", subjects=subjects_with_chapters, users=users)

    return redirect(url_for("login"))

@app.route("/admin/statistics")
def admin_statistics():
    if "user" in session and session.get("is_admin"):
        conn = sqlite3.connect("database.db")
        c = conn.cursor()

        # Fetch total users, active users, and blocked users
        c.execute("SELECT COUNT(*) FROM users")
        total_users = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM users WHERE is_blocked = 0")
        active_users = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM users WHERE is_blocked = 1")
        blocked_users = c.fetchone()[0]

        # Fetch total quizzes
        c.execute("SELECT COUNT(*) FROM quizzes")
        total_quizzes = c.fetchone()[0]

        # Fetch most attempted quiz
        c.execute("""
            SELECT quizzes.id, chapters.name, COUNT(scores.id) as attempts
            FROM scores
            JOIN quizzes ON scores.quiz_id = quizzes.id
            JOIN chapters ON quizzes.chapter_id = chapters.id
            GROUP BY quizzes.id
            ORDER BY attempts DESC
            LIMIT 1
        """)
        most_attempted_quiz = c.fetchone()
        if not most_attempted_quiz:
            most_attempted_quiz = (0, "No quizzes attempted yet", 0)

        # Fetch quiz attempts data for chart
        c.execute("""
            SELECT chapters.name, COUNT(scores.id)
            FROM scores
            JOIN quizzes ON scores.quiz_id = quizzes.id
            JOIN chapters ON quizzes.chapter_id = chapters.id
            GROUP BY quizzes.id
        """)
        quiz_data = c.fetchall()

        quiz_labels = [row[0] for row in quiz_data]
        quiz_attempts = [row[1] for row in quiz_data]

        conn.close()
        return render_template("admin_statistics.html",
                               total_users=total_users,
                               active_users=active_users,
                               blocked_users=blocked_users,
                               total_quizzes=total_quizzes,
                               most_attempted_quiz=most_attempted_quiz,
                               quiz_labels=quiz_labels,
                               quiz_attempts=quiz_attempts)

    return redirect(url_for("login"))

@app.route("/admin/add_subject", methods=["POST"])
def add_subject():
    if "user" in session and session.get("is_admin"):
        subject_name = request.form["subject_name"]
        subject_desc = request.form["subject_desc"]  # ✅ Get description from form

        conn = sqlite3.connect("database.db")
        c = conn.cursor()
        c.execute("INSERT INTO subjects (name, description) VALUES (?, ?)", (subject_name, subject_desc))  # ✅ Include description
        conn.commit()
        conn.close()
        
        return redirect(url_for("admin_dashboard"))
    
    return redirect(url_for("login"))


@app.route("/admin/add_chapter", methods=["POST"])
def add_chapter():
    if "user" in session and session.get("is_admin"):
        subject_id = request.form["subject_id"]
        chapter_name = request.form["chapter_name"]
        conn = sqlite3.connect("database.db")
        c = conn.cursor()
        c.execute(
            "INSERT INTO chapters (subject_id, name) VALUES (?, ?)",
            (subject_id, chapter_name),
        )
        conn.commit()
        conn.close()
        return redirect(url_for("admin_dashboard"))
    return redirect(url_for("login"))


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        email = request.form["email"]
        password = generate_password_hash(request.form["password"])  # Hash password
        full_name = request.form["full_name"]
        qualification = request.form["qualification"]
        dob = request.form["dob"]

        conn = sqlite3.connect("database.db")
        c = conn.cursor()
        try:
            c.execute(
                "INSERT INTO users (email, password, full_name, qualification, dob) VALUES (?, ?, ?, ?, ?)",
                (email, password, full_name, qualification, dob),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            return "Email already exists"
        finally:
            conn.close()

        return redirect(url_for("login"))

    return render_template("signup.html")




@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        conn = sqlite3.connect("database.db")
        c = conn.cursor()
        c.execute("SELECT id, password, is_admin, is_blocked FROM users WHERE email = ?", (email,))
        user = c.fetchone()
        conn.close()

        if user:
            if user[3] == 1:  # ✅ Check if user is blocked
                return "Your account is blocked. Contact the admin."
            
            if check_password_hash(user[1], password):  # Verify password
                session["user_id"] = user[0]
                session["user"] = email
                session["is_admin"] = user[2]
                if user[2]:  # Redirect admin
                    return redirect(url_for("admin_dashboard"))
                return redirect(url_for("home"))
            else:
                return "Invalid email or password"

    return render_template("login.html")

@app.route("/admin/block_user/<int:user_id>", methods=["POST"])
def block_user(user_id):
    if "user" in session and session.get("is_admin"):
        conn = sqlite3.connect("database.db")
        c = conn.cursor()
        c.execute("UPDATE users SET is_blocked = 1 WHERE id = ?", (user_id,))
        conn.commit()
        conn.close()
        return redirect(url_for("admin_dashboard"))
    return redirect(url_for("login"))


@app.route("/admin/unblock_user/<int:user_id>", methods=["POST"])
def unblock_user(user_id):
    if "user" in session and session.get("is_admin"):
        conn = sqlite3.connect("database.db")
        c = conn.cursor()
        c.execute("UPDATE users SET is_blocked = 0 WHERE id = ?", (user_id,))
        conn.commit()
        conn.close()
        return redirect(url_for("admin_dashboard"))
    return redirect(url_for("login"))


@app.route("/admin/edit_subject/<int:subject_id>", methods=["POST"])
def edit_subject(subject_id):
    if "user" in session and session.get("is_admin"):
        new_name = request.form["new_name"]
        new_desc = request.form["new_desc"]
        conn = sqlite3.connect("database.db")
        c = conn.cursor()
        c.execute("UPDATE subjects SET name = ?, description = ? WHERE id = ?", (new_name, new_desc, subject_id))
        conn.commit()
        conn.close()
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/delete_subject/<int:subject_id>", methods=["POST"])
def delete_subject(subject_id):
    if "user" in session and session.get("is_admin"):
        conn = sqlite3.connect("database.db")
        c = conn.cursor()

        # Get all chapters under this subject
        c.execute("SELECT id FROM chapters WHERE subject_id = ?", (subject_id,))
        chapters = [row[0] for row in c.fetchall()]

        for chapter_id in chapters:
            # Get all quizzes under this chapter
            c.execute("SELECT id FROM quizzes WHERE chapter_id = ?", (chapter_id,))
            quizzes = [row[0] for row in c.fetchall()]

            for quiz_id in quizzes:
                # Delete all questions under this quiz
                c.execute("DELETE FROM questions WHERE quiz_id = ?", (quiz_id,))

            # Delete all quizzes under this chapter
            c.execute("DELETE FROM quizzes WHERE chapter_id = ?", (chapter_id,))

            # Delete the chapter itself
            c.execute("DELETE FROM chapters WHERE id = ?", (chapter_id,))

        # Finally, delete the subject
        c.execute("DELETE FROM subjects WHERE id = ?", (subject_id,))

        conn.commit()
        conn.close()
    
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/edit_chapter/<int:chapter_id>", methods=["POST"])
def edit_chapter(chapter_id):
    if "user" in session and session.get("is_admin"):
        new_name = request.form["new_name"]
        conn = sqlite3.connect("database.db")
        c = conn.cursor()
        c.execute("UPDATE chapters SET name = ? WHERE id = ?", (new_name, chapter_id))
        conn.commit()
        conn.close()
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/delete_chapter/<int:chapter_id>", methods=["POST"])
def delete_chapter(chapter_id):
    if "user" in session and session.get("is_admin"):
        conn = sqlite3.connect("database.db")
        c = conn.cursor()

        # Get all quizzes under this chapter
        c.execute("SELECT id FROM quizzes WHERE chapter_id = ?", (chapter_id,))
        quizzes = [row[0] for row in c.fetchall()]

        for quiz_id in quizzes:
            # Delete all questions under this quiz
            c.execute("DELETE FROM questions WHERE quiz_id = ?", (quiz_id,))

        # Delete all quizzes under this chapter
        c.execute("DELETE FROM quizzes WHERE chapter_id = ?", (chapter_id,))

        # Delete the chapter itself
        c.execute("DELETE FROM chapters WHERE id = ?", (chapter_id,))

        conn.commit()
        conn.close()
    
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/edit_quiz/<int:quiz_id>", methods=["POST"])
def edit_quiz(quiz_id):
    if "user" in session and session.get("is_admin"):
        new_date = request.form["new_date"]
        new_duration = request.form["new_duration"]
        conn = sqlite3.connect("database.db")
        c = conn.cursor()
        c.execute("UPDATE quizzes SET date_of_quiz = ?, time_duration = ? WHERE id = ?", (new_date, new_duration, quiz_id))
        conn.commit()
        conn.close()
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/delete_quiz/<int:quiz_id>", methods=["POST"])
def delete_quiz(quiz_id):
    if "user" in session and session.get("is_admin"):
        conn = sqlite3.connect("database.db")
        c = conn.cursor()

        # Delete all questions under this quiz
        c.execute("DELETE FROM questions WHERE quiz_id = ?", (quiz_id,))

        # Delete the quiz itself
        c.execute("DELETE FROM quizzes WHERE id = ?", (quiz_id,))

        conn.commit()
        conn.close()
    
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/edit_question/<int:question_id>", methods=["POST"])
def edit_question(question_id):
    if "user" in session and session.get("is_admin"):
        new_question = request.form["new_question"]
        option1 = request.form["option1"]
        option2 = request.form["option2"]
        option3 = request.form["option3"]
        option4 = request.form["option4"]
        correct_option = int(request.form["correct_option"])  # Ensure it's stored as an integer

        conn = sqlite3.connect("database.db")
        c = conn.cursor()
        c.execute("""
            UPDATE questions 
            SET question_statement = ?, option1 = ?, option2 = ?, option3 = ?, option4 = ?, correct_option = ? 
            WHERE id = ?
        """, (new_question, option1, option2, option3, option4, correct_option, question_id))

        conn.commit()
        conn.close()
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/delete_question/<int:question_id>", methods=["POST"])
def delete_question(question_id):
    if "user" in session and session.get("is_admin"):
        conn = sqlite3.connect("database.db")
        c = conn.cursor()
        c.execute("DELETE FROM questions WHERE id = ?", (question_id,))
        conn.commit()
        conn.close()
    return redirect(url_for("admin_dashboard"))

@app.route("/logout")
def logout():
    session.pop("user", None)
    session.pop("user_id", None)
    session.pop("is_admin", None)
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True)
