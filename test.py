import streamlit as st
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from google.oauth2 import credentials as google_credentials

# OAuth 2.0 client ID and scopes
CLIENT_ID = ''
CLIENT_SECRET = ''
PROJECT_ID = ''
SCOPES = ['https://www.googleapis.com/auth/webmasters.readonly']

# Function to get OAuth2 details from the user
def get_oauth2_details():
    global CLIENT_ID, CLIENT_SECRET, PROJECT_ID
    
    CLIENT_ID = st.text_input("Enter your Client ID:")
    CLIENT_SECRET = st.text_input("Enter your Client Secret:", type="password")
    PROJECT_ID = st.text_input("Enter your Project ID:")

# Function to obtain an access token
def obtain_access_token():
    # Use global CLIENT_ID and CLIENT_SECRET
    global CLIENT_ID, CLIENT_SECRET, PROJECT_ID
    
    # Prepare the client_config
    client_config = {
        "installed": {
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "project_id": PROJECT_ID,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": [
        "http://localhost"]
        }
    }

    flow = InstalledAppFlow.from_client_config(client_config, SCOPES)

    credentials_obj = flow.run_local_server(port=0)

    # Check if credentials have been obtained
    if credentials_obj:
        st.success("Access token obtained successfully!")
        return credentials_obj.token
    else:
        return None
    
def main():
    if 'oauth2_set' not in st.session_state:
        st.session_state.oauth2_set = False

        # Input the OAuth2 details
    with st.expander("Enter OAuth2 Details", expanded=st.session_state.oauth2_expander_state):
        get_oauth2_details()

        if st.button("Set OAuth2 Details"):
            st.session_state.oauth2_set = True
            st.session_state.oauth2_expander_state = True  # Update the session state variable to keep expander expanded
            st.success("OAuth2 details set successfully!")

        # Only allow the user to obtain an access token if OAuth2 details are set
        if st.session_state.oauth2_set:
            with st.form("new_form"):
                if st.form_submit_button("Obtain Access Token"):
                    access_token = obtain_access_token()
                    if access_token is not None:
                        st.session_state.access_token = access_token

                st.info("Click the button above to obtain an access token.")

                if 'access_token' not in st.session_state or st.session_state.access_token is None:
                    st.warning("Access token not available. Please obtain an access token.")
                    return

if 'oauth2_expander_state' not in st.session_state:
    st.session_state.oauth2_expander_state = False

if __name__ == "__main__":
    main()