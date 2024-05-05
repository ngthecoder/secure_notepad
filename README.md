This is a project for CNIT315.

Objective: Create a notepad-ish program in C that stores messages securely using RSA encryption.

Contributors: K.H, N.G
K.H: 
- Recreate the algorithm in C
- Organize the programs in main()

N.G:
- Manage the data coming in and out of the database
- Create the UI

Milestones:
- 2/26 Presentation Proposal Due (Done)
- 3/7 - Update
- 3/14 - Update
- 3/21 - Update
- 3/27 - Update
- 4/1 Finish Algorithm / Finish Database Setup
- 4/14 Program Completed / Practice Presentation
- 4/21 Presentation Due

ERD and Logic Flow attached as images

Command to compile:
gcc -o main main.c sqlite/sqlite3.c -Isqlite -lpthread -ldl
gcc -o main main.c -Isqlite -lpthread -ldl -lssl -lcrypto
(final) gcc main.c -o main -lsqlite3 -lcrypto -ldl