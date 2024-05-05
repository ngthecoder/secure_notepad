# Secure Notepad Project
This project is a secure notepad application implemented in C, utilizing the RSA encryption algorithm and SQLite database for user management and note storage. The application allows users to register, login, create, view, and delete encrypted notes.
## Features
- User registration and login functionality
- RSA encryption for secure note storage
- SQLite database for user and note management
- Ability to create, view (encrypted and decrypted), and delete notes
- Command-line user interface
## Requirements
- C compiler (e.g., GCC)
- SQLite3 library
- OpenSSL library
## Setup
1. Clone the repository:
   ```
   git clone https://github.com/ngthecoder/secure_notepad
   ```
2. Navigate to the project directory:
   ```
   cd secure_notepad
   ```
3. Compile the project:
   ```
   gcc -o main main.c -lsqlite3 -lcrypto
   ```
4. Run the application:
   ```
   ./main
   ```
## Usage
1. Upon running the application, you will be prompted to choose an option: register, login, or exit.
2. If you are a new user, select "register" and provide a unique username and password.
3. If you are a registered user, select "login" and enter your username and password.
4. Once logged in, you can choose from the following options:
   - add_memo: Enter a new note to be encrypted and stored.
   - view_encrypted_memos: View your notes in encrypted form.
   - view_decrypted_memos: View your notes in decrypted form.
   - remove_memo: Delete a note by providing its ID.
   - logout: Log out of the application.
5. Follow the prompts to perform the desired actions.
## Implementation Details
- The RSA encryption algorithm is implemented using the OpenSSL library. If the RSA key pair is not found, the application generates a new 2048-bit key pair.
- SQLite is used as the database to store user information and encrypted notes. The application creates two tables: "Users" for user credentials and "Memos" for storing notes.
- User registration and authentication are performed using SQLite queries to ensure secure access to the application.
- Notes are encrypted using the RSA public key before being stored in the database and decrypted using the RSA private key when viewed by the user.
## Future Improvements
- Input validation and data sanitization should be improved to handle invalid inputs and prevent potential errors or security vulnerabilities.
- The OpenSSL functions used in the project are marked as deprecated. Consider updating to newer encryption methods or libraries in future versions.
## Contributors
- [Rotoyu](https://github.com/Rotoyu)
- [ngthecoder](https://github.com/ngthecoder)
