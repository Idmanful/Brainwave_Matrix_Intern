import re
import tkinter as tk
from tkinter import messagebox

def assess_password_strength(password):
    """
    Assess the strength of a given password based on length, complexity, and uniqueness.
    Returns a feedback string with suggestions for improvement.
    """
    # Criteria weights
    MIN_LENGTH = 8
    STRONG_LENGTH = 12

    # Password assessment metrics
    length_score = len(password)
    has_lowercase = bool(re.search(r'[a-z]', password))
    has_uppercase = bool(re.search(r'[A-Z]', password))
    has_digits = bool(re.search(r'\d', password))
    has_special = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
    uniqueness_score = len(set(password)) / len(password) if len(password) > 0 else 0

    # Calculate password strength
    score = 0
    if length_score >= MIN_LENGTH:
        score += 1
    if length_score >= STRONG_LENGTH:
        score += 1
    if has_lowercase:
        score += 1
    if has_uppercase:
        score += 1
    if has_digits:
        score += 1
    if has_special:
        score += 1
    if uniqueness_score > 0.7:
        score += 1

    # Provide feedback based on score
    feedback = ""
    if score < 4:
        feedback = "Weak: Use at least 8 characters, mix letters (uppercase and lowercase), numbers, and special symbols."
    elif 4 <= score < 6:
        feedback = "Moderate: Consider increasing length to 12+ characters and adding more diverse symbols."
    else:
        feedback = "Strong: Your password is robust!"

    return {
        "score": score,
        "feedback": feedback
    }

def evaluate_password():
    password = password_entry.get()
    if not password:
        messagebox.showwarning("Input Error", "Please enter a password.")
        return
    result = assess_password_strength(password)
    score_label.config(text=f"Score: {result['score']}/7")
    feedback_label.config(text=f"Feedback: {result['feedback']}")

def toggle_password_visibility():
    if password_entry.cget('show') == '*':
        password_entry.config(show='')
        toggle_button.config(text="Hide Password")
    else:
        password_entry.config(show='*')
        toggle_button.config(text="Show Password")

# Create GUI
root = tk.Tk()
root.title("Password Strength Checker")

# Input field
frame = tk.Frame(root, padx=20, pady=20)
frame.pack()

password_label = tk.Label(frame, text="Enter Password:")
password_label.grid(row=0, column=0, sticky="w")

password_entry = tk.Entry(frame, show="*", width=30)
password_entry.grid(row=0, column=1, padx=10)

# Toggle password visibility button
toggle_button = tk.Button(frame, text="Show Password", command=toggle_password_visibility)
toggle_button.grid(row=0, column=2, padx=10)

# Evaluate button
evaluate_button = tk.Button(frame, text="Evaluate", command=evaluate_password)
evaluate_button.grid(row=1, column=0, columnspan=3, pady=10)

# Results
score_label = tk.Label(frame, text="Score: ")
score_label.grid(row=2, column=0, columnspan=3, sticky="w")

feedback_label = tk.Label(frame, text="Feedback: ", wraplength=400, justify="left")
feedback_label.grid(row=3, column=0, columnspan=3, sticky="w")

# Run the application
root.mainloop()
