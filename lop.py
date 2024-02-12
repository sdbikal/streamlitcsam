#!/usr/bin/env python
# coding: utf-8

# In[4]:


import streamlit as st
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
import joblib
import sqlite3
import requests
from datetime import datetime


# Load the dataset
dataset = pd.read_excel('csam_benign.xlsx')
X = dataset['url']
y = dataset['type']

# Feature extraction using TfidfVectorizer
tfidf_vectorizer = TfidfVectorizer(max_features=5000)
X_tfidf = tfidf_vectorizer.fit_transform(X)

# Training best model from Approach 1 method: Random Forest model
random_forest_model = RandomForestClassifier(n_estimators=100, random_state=42)
random_forest_model.fit(X_tfidf, y)

# Save the trained model to a file
model_filename = 'random_forest_model8.joblib'
joblib.dump(random_forest_model, model_filename)

# Function to classify text
def classify_text(text):
    loaded_model = joblib.load(model_filename)
    text_tfidf = tfidf_vectorizer.transform([text])
    probabilities = loaded_model.predict_proba(text_tfidf)
    prediction = loaded_model.predict(text_tfidf)[0]
    return prediction, probabilities

# Function to create a SQLite database table (run this once)
def create_user_table():
    conn = sqlite3.connect('user_data.db')
    c = conn.cursor()
    c.execute('CREATE TABLE IF NOT EXISTS users (username TEXT, password TEXT)')
    conn.commit()
    conn.close()

# Function to insert a new user into the database
def insert_user_into_db(username, password):
    conn = sqlite3.connect('user_data.db')
    c = conn.cursor()
    c.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
    conn.commit()
    conn.close()

# Function to check user credentials against the database
def check_user_in_db(username, password):
    conn = sqlite3.connect('user_data.db')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE username=? AND password=?', (username, password))
    result = c.fetchone()
    conn.close()
    return result is not None

# Function to get all registered users
def get_all_registered_users():
    conn = sqlite3.connect('user_data.db')
    c = conn.cursor()
    c.execute('SELECT username FROM users')
    users = [row[0] for row in c.fetchall()]
    conn.close()
    return users

# Function to get the role of a user
def get_user_role(username):
    conn = sqlite3.connect('user_data.db')
    c = conn.cursor()
    c.execute('SELECT role FROM user_roles WHERE username=?', (username,))
    result = c.fetchone()
    conn.close()
    return result[0] if result else None
def assign_role(username, role):
    conn = sqlite3.connect('user_data.db')
    c = conn.cursor()

    # Check if the user already has a role
    c.execute('SELECT role FROM user_roles WHERE username=?', (username,))
    existing_role = c.fetchone()

    if existing_role:
        # If the user already has a role, update it
        c.execute('UPDATE user_roles SET role=? WHERE username=?', (role, username))
    else:
        # If the user does not have a role, insert a new record
        c.execute('INSERT INTO user_roles (username, role) VALUES (?, ?)', (username, role))

    conn.commit()
    conn.close()
# Create a new SQLite database table for link feedback (run this once)
def create_feedback_table():
    conn = sqlite3.connect('user_data.db')
    c = conn.cursor()
    c.execute('CREATE TABLE IF NOT EXISTS link_feedback (username TEXT, link TEXT, is_valid BOOLEAN, feedback TEXT, timestamp TEXT)')
    conn.commit()
    conn.close()
# Function to insert link validation feedback into the database
def insert_feedback(username, link, is_valid, feedback):
    conn = sqlite3.connect('user_data.db')
    c = conn.cursor()
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    c.execute('INSERT INTO link_feedback (username, link, is_valid, feedback, timestamp) VALUES (?, ?, ?, ?, ?)',
              (username, link, is_valid, feedback, timestamp))
    conn.commit()
    conn.close()


# Function for login page
def login_page():
    st.subheader("Login")
    username = st.text_input("Username:")
    password = st.text_input("Password:", type="password")

    if st.button("Login"):
        if check_user_in_db(username, password):
            st.session_state.logged_in = True
            st.session_state.current_user = username
            st.success("Login successful!")
        else:
            st.error("Invalid login credentials. Please register first.")
    if st.button("Logout"):
        st.session_state.logged_in=False
        st.session_state.current_user=None

# Function for link and file classification page
def expand_short_url(short_url):
    try:
        response = requests.head(short_url, allow_redirects=True)
        long_url = response.url
        return long_url
    except Exception as e:
        print(f"Error expanding short URL: {e}")
        return None


# Function for link and file classification page
# Function for link and file classification page
def link_classification_page():
    st.header("Link detection or upload file having a list of links to classify")
    # Check if the user is logged in
    if not st.session_state.logged_in:
        st.warning("Please log in first to access this page.")
        return

    # Option to enter a URL
    user_input_link = st.text_input("Enter Link to detect:")

    # Option to upload an Excel file
    uploaded_file = st.file_uploader("Upload Excel file", type=["xlsx", "xls"])

    # Checkbox for removing spaces in URL
    remove_spaces = st.checkbox("Remove Spaces in URL")

    # Checkbox for converting short URL to long URL
    convert_short_url = st.checkbox("Convert Short URL to Long URL")
    if st.button("Classify"):
        if user_input_link:
            # Remove spaces if the checkbox is checked
            if remove_spaces:
                user_input_link = user_input_link.replace(" ", "")

            # Convert short URL to long URL if the checkbox is checked
            if convert_short_url:
                expanded_url = expand_short_url(user_input_link)
                if expanded_url:
                    user_input_link = expanded_url
                    st.success(f"Expanded URL: {expanded_url}")
                else:
                    st.warning("Failed to expand the short URL. Prediction will be performed on the original URL.")

            # Perform classification for link
            prediction_link, probabilities = classify_text(user_input_link)
            # Convert probabilities to percentage scale
            csam_probability = round(probabilities[0][1] * 100, 2)
            benign_probability = round(probabilities[0][0] * 100, 2)
            st.success(f"Predicted Class (Link): {prediction_link}")
            st.write(f"Probability of being CSAM: {csam_probability}%")
            st.write(f"Probability of being benign: {benign_probability}%")
            if prediction_link == "CSAM":
                st.link_button("Report to IWF", "https://report.iwf.org.uk/en", help=None, type="secondary",
                               disabled=False, use_container_width=False)
                import webbrowser
                webbrowser.open_new_tab("https://report.iwf.org.uk/en")
        elif uploaded_file is not None:
            # Read Excel file
            df = pd.read_excel(uploaded_file)

            # Assuming 'url' is the name of the column containing URLs
            df['Predicted_Class'], df['CSAM_Probability'], df['Benign_Probability'] = zip(
                *df['url'].apply(lambda x: classify_text(x)))
            # Convert probabilities to percentage scale for the DataFrame
            df['CSAM_Probability'] = df['CSAM_Probability'].apply(lambda x: round(x * 100, 2))
            df['Benign_Probability'] = df['Benign_Probability'].apply(lambda x: round(x * 100, 2))
            # Display the DataFrame with predictions
            #st.dataframe(df)
        else:
            st.warning("Please enter a link or upload an Excel file for classification.")
    
            
          
    if st.button("Logout",key="logout_button"):
        st.session_state.logged_in=False
        st.session_state.current_user=None





# Function for registration page
def registration_page():
    st.subheader("Registration")
    new_username = st.text_input("New Username:")
    new_password = st.text_input("New Password:", type="password")

    if st.button("Register"):
        if check_user_in_db(new_username, new_password):
            st.warning("Username already exists. Please choose a different one.")
        else:
            insert_user_into_db(new_username, new_password)
            st.success("Registration successful. Please log in.")

# Function for admin dashboard page

# Function for the admin dashboard page
def admin_dashboard_page():
    st.header("Administrator Dashboard")

    # Display a list of registered users with an option to assign roles
    registered_users = get_all_registered_users()
    selected_users = st.multiselect("Select users to assign roles", registered_users)
    selected_role = st.selectbox("Select role to assign", ["Super User", "Data Scientist", "User"])

    if st.button("Assign Roles"):
        for user in selected_users:
            assign_role(user, selected_role)
        st.success("Roles assigned successfully.")
# Function for link feedback page
def link_feedback_page():
    st.header("Link Validation Feedback")

    # Check if the user is logged in
    if not st.session_state.logged_in:
        st.warning("Please log in first to access this page.")
        return

    # Option to enter the link for feedback
    user_input_link = st.text_input("Enter Link for Feedback:")
    # Option to upload an Excel file
    uploaded_file = st.file_uploader("Upload Excel file having links", type=["xlsx", "xls"])


    # Checkbox for indicating whether the link validation was correct or not
    is_valid = st.checkbox("Validated Correctly")
    is_valid=st.checkbox("Validated Incorrectly")

    # Text area for user feedback
    feedback_text = st.text_area("Additional Feedback (optional):")

    if st.button("Submit Feedback"):
        # Insert feedback into the database
        insert_feedback(st.session_state.current_user, user_input_link, is_valid, feedback_text)
        st.success("Feedback submitted successfully.")

# Main function
def main():
    st.title("CSAM Link Detection App")

    # Create the user table in the database (run this once)
    create_user_table()
    create_feedback_table()


    # Initialize session state for login status
    if 'logged_in' not in st.session_state:
        st.session_state.logged_in = False

    # Navigation sidebar
    page = st.sidebar.selectbox("Select Page", ["Login", "Link and File Classification", "Link Feedback", "Registration", "Admin Dashboard"])

    # Run the selected page function
    if page == "Login":
        login_page()
    elif page == "Link and File Classification":
        link_classification_page()
    elif page == "Registration":
        registration_page()
    elif page == "Admin Dashboard":
        admin_dashboard_page()
    elif page == "Link Feedback":
        link_feedback_page()

if __name__ == "__main__":
    main()


# In[ ]:




