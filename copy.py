#!/usr/bin/env python
# coding: utf-8

# In[3]:


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
    # Check if username and password match the common credentials
    return username == "admin" and password == "admin"

# Function to get all registered users
def get_all_registered_users():
    conn = sqlite3.connect('user_data.db')
    c = conn.cursor()
    c.execute('SELECT username FROM users')
    users = [row[0] for row in c.fetchall()]
    conn.close()
    return users





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



# Main function
def main():
    st.title("CSAM Link Detection App")

    # Create the user table in the database (run this once)
    create_user_table()
    


    # Initialize session state for login status
    if 'logged_in' not in st.session_state:
        st.session_state.logged_in = False

    # Navigation sidebar
    page = st.sidebar.selectbox("Select Page", ["Login", "Link and File Classification"])

    # Run the selected page function
    if page == "Login":
        login_page()
    elif page == "Link and File Classification":
        link_classification_page()
    

if __name__ == "__main__":
    main()


# In[ ]:




