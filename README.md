# 🔒 Secure Data Encryption System

A Streamlit-based secure data storage and retrieval system that uses strong encryption to protect sensitive information.

## Features

- 🔐 Secure encryption using Fernet (symmetric encryption)
- 🔑 PBKDF2 password hashing for enhanced security
- ⚠️ Account lockout after multiple failed attempts
- 💾 Persistent data storage in JSON format
- 🎨 User-friendly Streamlit interface
- 🔄 Session management and authentication

## Installation

1. Clone this repository
2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

1. Run the Streamlit app:
   ```bash
   streamlit run app.py
   ```

2. Access the application in your web browser (typically at http://localhost:8501)

3. Use the navigation menu to:
   - Store new encrypted data
   - Retrieve existing data
   - Manage authentication

## Security Features

- **Encryption**: Uses Fernet (symmetric encryption) for data protection
- **Password Hashing**: Implements PBKDF2 for secure password storage
- **Account Lockout**: Locks account after 3 failed attempts for 5 minutes
- **Salt-based Encryption**: Each encryption uses a unique salt
- **Session Management**: Tracks user sessions and authentication state

## Default Credentials

- Username: `admin`
- Password: `admin123`

*Note: In a production environment, these credentials should be changed and stored securely.*

## File Structure

- `app.py`: Main application file
- `requirements.txt`: Project dependencies
- `encrypted_data.json`: Stores encrypted data (created automatically)

## Security Considerations

- This is a demonstration project. For production use:
  - Implement proper user authentication
  - Use secure key management
  - Store credentials in a secure database
  - Implement proper session management
  - Use HTTPS for all communications

## License

This project is open source and available under the MIT License.

## Creator

- **Muhammad Sami**
  - [GitHub](https://github.com/muhammadsami987123)
  - [LinkedIn](https://www.linkedin.com/in/muhammad-sami-3aa6102b8/)
  - [X (Twitter)](https://x.com/MSAMIWASEEM1) 