#!/usr/bin/env python
# coding: utf-8

# In[2]:


import streamlit as st
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
import joblib
import requests
from urllib.parse import urlparse

# Load the dataset
dataset = pd.read_excel('csam_benign_added.xlsx')

# Assuming you have 'text' column in your dataset containing textual data
X = dataset['url']
y = dataset['type']  # Replace 'label' with the actual column name containing the target variable

# Split the data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Feature extraction using TfidfVectorizer
tfidf_vectorizer = TfidfVectorizer(max_features=20000)  # You can adjust max_features based on your dataset size
X_train_tfidf = tfidf_vectorizer.fit_transform(X_train)
X_test_tfidf = tfidf_vectorizer.transform(X_test)

# Train a Random Forest model
random_forest_model = RandomForestClassifier(n_estimators=100, random_state=42)
random_forest_model.fit(X_train_tfidf, y_train)

# Save the trained model to a file
model_filename = 'random_forest_model.joblib'
joblib.dump(random_forest_model, model_filename)

# Function to classify a single URL and return probabilities
def classify_single_url(url):
    # Load the saved model
    loaded_model = joblib.load(model_filename)

    # Feature extraction using TfidfVectorizer
    url_tfidf = tfidf_vectorizer.transform([url])

    # Perform classification and get probabilities
    probabilities = loaded_model.predict_proba(url_tfidf)[0]
    
    # Classify the URL
    predicted_class = loaded_model.predict(url_tfidf)[0]

    # Get the probability of being benign and CSAM
    probability_benign = probabilities[0]*100
    probability_csam = probabilities[1]*100
    
    # Convert short URL to long URL
    try:
        response = requests.head(url, allow_redirects=True)
        long_url = response.url
    except Exception as e:
        st.error(f"Error: {e}")
        long_url = None

    return predicted_class, probability_benign, probability_csam, long_url
# Function to convert short URL to long URL
def expand_short_url(short_url):
    try:
        response = requests.head(short_url, allow_redirects=True)
        long_url = response.url
        return long_url
    except Exception as e:
        st.error(f"Error: {e}")
        return None
# Function to remove spaces from a string
def remove_spaces(text):
    return text.replace(" ", "")

# Streamlit app
def main():
    st.title("URL Classification App")

    # Login Page
    username = st.text_input("Username:")
    password = st.text_input("Password:", type="password")

    if st.button("Login"):
        if username == "admin" and password == "admin":
            st.success("Login successful!")
            st.session_state.logged_in = True
        else:
            st.error("Invalid username or password!")

    # Only proceed if logged in
    if 'logged_in' in st.session_state and st.session_state.logged_in:
        st.header("URL Classification")

        # Option to enter a URL
        user_input_url = st.text_input("Enter URL to detect:")

        # Checkbox to convert short URL to long URL
        expand_url_checkbox = st.checkbox("Convert short URL to long URL")

        # Checkbox to remove spaces
        remove_spaces_checkbox = st.checkbox("Remove spaces")

        # Option to upload an Excel file
        uploaded_file = st.file_uploader("Upload Excel file", type=["xlsx", "xls"])

        if st.button("Classify"):
            if user_input_url:
                # Additional processing based on checkboxes
                if expand_url_checkbox:
                    long_url = expand_short_url(user_input_url)
                    if long_url:
                        st.success(f"Long URL: {long_url}")
                        user_input_url = long_url

                if remove_spaces_checkbox:
                    user_input_url = remove_spaces(user_input_url)

                # Perform classification for URL
                predicted_class, prob_benign, prob_csam, long_url = classify_single_url(user_input_url)
                st.success(f"Predicted Class: {predicted_class}")
                st.success(f"Probability of being benign: {prob_benign:.2f}%")
                st.success(f"Probability of being CSAM: {prob_csam:.2f}%")

            elif uploaded_file is not None:
                # Read Excel file
                df = pd.read_excel(uploaded_file)

                # Additional processing based on checkboxes
                if remove_spaces_checkbox:
                    df['url'] = df['url'].apply(remove_spaces)

                if expand_url_checkbox:
                    df['url'] = df['url'].apply(expand_short_url)

                # Classify URLs
                df['Predicted_Class'], df['Probability_Benign'], df['Probability_CSAM'], df['Long_URL'] = zip(*df['url'].apply(classify_single_url))

                # Display the DataFrame with predictions
                st.dataframe(df)
            else:
                st.warning("Please enter a URL or upload an Excel file for classification.")

if __name__ == "__main__":
    main()


# In[ ]:




