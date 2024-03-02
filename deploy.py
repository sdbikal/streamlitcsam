#!/usr/bin/env python
# coding: utf-8

# In[7]:


import streamlit as st
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
import joblib
import requests

# Function to convert short URL to long URL
def expand_short_url(short_url):
    try:
        response = requests.head(short_url, allow_redirects=True)
        long_url = response.url
        return long_url
    except Exception as e:
        st.error(f"Error expanding short URL: {e}")
        return None

# Function to remove spaces from a string
def remove_spaces(text):
    return text.replace(" ", "")

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

def classify_single_url(url):
    try:
        # Load the saved model
        loaded_model = joblib.load(model_filename, mmap_mode='r')

        # Feature extraction using TfidfVectorizer
        url_tfidf = tfidf_vectorizer.transform([url])

        # Perform classification and get probabilities
        probabilities = loaded_model.predict_proba(url_tfidf)[0]

        # Classify the URL
        predicted_class = loaded_model.predict(url_tfidf)[0]

        # Get the probability of being benign and CSAM
        probability_benign = probabilities[0] * 100
        probability_csam = probabilities[1] * 100

        # Convert short URL to long URL
        try:
            response = requests.head(url, allow_redirects=True)
            long_url = response.url
        except Exception as e:
            st.error(f"Error fetching URL: {e}")
            long_url = None

        return predicted_class, (probability_benign, probability_csam), long_url
    except Exception as e:
        st.error(f"Error loading model: {e}")
        return None, None, None

def main():
    st.title("CSAMGuard App: To Detect URLs as CSAM or Benign")

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
                predicted_class, probabilities, long_url = classify_single_url(user_input_url)
                if predicted_class is not None:
                    st.success(f"Predicted Class: {predicted_class}")
                    st.success(f"Probability of being benign: {probabilities[0]:.2f}%")
                    st.success(f"Probability of being CSAM: {probabilities[1]:.2f}%")
                    if predicted_class == "CSAM":
                        st.link_button("Report to IWF", "https://report.iwf.org.uk/en", help=None, type="secondary",
                               disabled=False, use_container_width=False)
                        import webbrowser
                        webbrowser.open_new_tab("https://report.iwf.org.uk/en")
            elif uploaded_file is not None:
                # Read Excel file
                df = pd.read_excel(uploaded_file, header=None)

                # Perform classification for each link in the Excel file
                predictions = []
                csam_probabilities = []
                benign_probabilities = []
                
                for link in df.iloc[:, 0]:
                    prediction, probabilities, long_url = classify_single_url(link)
                    predictions.append(prediction)
                    csam_probabilities.append(probabilities[1])  # CSAM probability
                    benign_probabilities.append(probabilities[0])  # Benign probability
                    

                # Create DataFrame to display predictions
                result_df = pd.DataFrame({
                    'Link': df.iloc[:, 0],
                    'Predicted_Class': predictions,
                    'CSAM_Probability': csam_probabilities,
                    'Benign_Probability': benign_probabilities,
                    
                })

                # Display the DataFrame with predictions
                st.dataframe(result_df)
            else:
                st.warning("Please enter a link or upload an Excel file for classification.")

    if st.button("Logout"):
        st.session_state.logged_in = False
        st.session_state.current_user = None

if __name__ == "__main__":
    main()


# In[ ]:




