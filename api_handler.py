import requests
import logging
import json
from time import time
from typing import Dict, Any
import os

default_url =  "127.0.0.1:8000"  # Default URL for the API (can be overridden by providing a different URL when initializing the APIHandler)

logger = logging.getLogger("APIHandler")

class APIHandler:
    def __init__(self, base_url=None, username=None, password=None, api_key=None):
        self.session = requests.Session()  # Create a session object to persist parameters across requests (e.g., authentication tokens)                             
        self.session.default_headers = {'accept: application/json'}  # Set default headers for the session (content type for JSON data)
        self.client_id = os.urandom(6).hex()  # Generate a random client ID for this instance of the API handler
        self.base_url = base_url
        if username and password:
            self.authResult = self._authenticate(username, password)
            logger.debug(f"Authentication result: {self.authResult}")
        elif api_key:
            self.api_key = api_key
        elif username or password:
            logger.error("Both username and password must be provided together for authentication.")
            raise ValueError("Both username and password must be provided together for authentication.")
        else:
            logger.error("No authentication credentials provided. Please provide either username/password or an API key.")
            raise ValueError("No authentication credentials provided. Please provide either username/password or an API key.")

    def _authenticate(self, username, password) -> Dict[str, Any]:
        """
        Internal method to authenticate with the API using username and password.
        It sends a POST request to the /auth/login endpoint and processes the response to extract the authentication token and other relevant information.
        
        Args:
            username (str): The username for authentication.
            password (str): The password for authentication.
        """
        #set usernmae and password variables
        self.username = username
        self.password = password

        logger.info(f"Attempting authentication for user: {self.username}")
        
        # Prepare the data payload for the authentication request
        self.data = {"username":self.username,"password":self.password,"client_id":f"tics-client-{self.client_id}"}

        self.request = self.session.post(f"{self.base_url}/auth/login", data=json.dumps(self.data)) # Send a POST request to the /auth/login endpoint with the username, password, and client ID as data
        
        # Evaluate the status code from the authentication request to determine if it was successful or if there was an error
        if self.request.status_code == 200:
            # Evaluate the content of the response to determine if authentication was successful and to extract the token and other relevant information
            if self.request.json().get("success"):
                self.token = self.request.json().get("token")
                self.token_expiry = self.request.json().get("expires_in") # Store the token expiry time (in seconds) for future reference when checking if the token needs to be refreshed
                self.token_issue_time = time()  # Store the time when the token was issued (in seconds)
                self.session.headers.update({"Authorization": f"Bearer {self.token}"})
                self.toReturn = {
                    "username": self.request.json().get("username"), 
                    "timeToExpire": self.request.json().get("expires_in")
                }
                logger.info("Authentication successful.")
                return self.toReturn
            else:
                logger.error("Authentication failed: API returned susccess=False.")
                logger.debug(f"API response: {self.request.json()}")
                raise Exception("Authentication failed: API returned success=False.")
        else:
            logger.error(f"Authentication failed with status code {self.request.status_code}: {self.request.text}")
            raise Exception(f"Authentication failed: {self.request.status_code}")

    def refresh_token(self):
        """
        Method to refresh the authentication token. 
        It checks if the token is about to expire and if so it sends a POST request to the /auth/refresh endpoint and updates the session with the new token if the refresh is successful.
        """
        logger.info("Checking if token refresh is needed...")
        self.current_time = time() # Get the current time in seconds
        if self.current_time >= self.token_issue_time + self.token_expiry - 60:  # Check if the current time is within 60 seconds of the token expiry time
            logger.info("Token is about to expire, attempting to refresh...")
            
            self.refresh_request = self.session.post(f"{self.base_url}/auth/refresh", data=json.dumps({"client_id": f"tics-client-{self.client_id}"}))  # Send a POST request to the /auth/refresh endpoint with the client ID as data
            
            #Check the status code of the refresh request to determine if it was successful or if there was an error
            if self.refresh_request.status_code == 200:
                #Checl if the refresh request was successful
                if self.refresh_request.json().get("success"):
                    self.token = self.refresh_request.json().get("token")
                    self.token_expiry = self.refresh_request.json().get("expires_in")
                    self.token_issue_time = time()
                    self.session.headers.update({"Authorization": f"Bearer {self.token}"})
                    logger.info("Token refreshed successfully.")
                else:
                    logger.error("Token refresh failed: API returned success=False.")
                    logger.debug(f"API response: {self.refresh_request.json()}")
            else:
                logger.error(f"Token refresh failed with status code {self.refresh_request.status_code}: {self.refresh_request.text}")
                raise Exception(f"Token refresh failed: {self.refresh_request.status_code}")
        else:
            logger.info(f"Token is still valid for {self.token_expiry} seconds, no refresh needed.")

    def get_data(self, endpoint):
        logger.info(f"Attempting to retrieve data from endpoint: {endpoint}")
        logger.debug(f"Using base URL: {self.base_url}")
        self.request = self.session.get(f"{self.base_url}/api/{endpoint}")
        return self.request.json()