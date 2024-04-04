#include <stdio.h>
#include <stdlib.h>
#include "RSA_Algorithm.h"  // Include the header file for RSA Algorithm declarations
#include <string.h>
#include <sqlite3.h>

void create_tables(sqlite3 *db) {
    char *err_msg = 0;
    const char *sql =
            "CREATE TABLE IF NOT EXISTS Users ("
            "UserID INTEGER PRIMARY KEY, "
            "Username TEXT NOT NULL, "
            "Password TEXT NOT NULL);"
            "CREATE TABLE IF NOT EXISTS Keys ("
            "KeyID INTEGER PRIMARY KEY, "
            "UserID INTEGER, "
            "PublicKey TEXT, "
            "PrivateKey TEXT, "
            "FOREIGN KEY(UserID) REFERENCES Users(UserID));"
            "CREATE TABLE IF NOT EXISTS Memos ("
            "MemoID INTEGER PRIMARY KEY, "
            "UserID INTEGER, "
            "Message TEXT, "
            "KeyID INTEGER, "
            "FOREIGN KEY(UserID) REFERENCES Users(UserID), "
            "FOREIGN KEY(KeyID) REFERENCES Keys(KeyID));";
    int rc = sqlite3_exec(db, sql, 0, 0, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", err_msg);
        sqlite3_free(err_msg);
    }
}

void register_user(sqlite3 *db, const char *username, const char *password) {
    sqlite3_stmt *stmt;
    const char *sql = "INSERT INTO Users (Username, Password) VALUES (?, ?);";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, password, -1, SQLITE_STATIC);
        if (sqlite3_step(stmt) != SQLITE_DONE) {
            fprintf(stderr, "Failed to add user: %s\n", sqlite3_errmsg(db));
        } else {
            printf("User registered successfully\n");
        }
        sqlite3_finalize(stmt);
    } else {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
    }
}

int authenticate(sqlite3 *db, const char *username, const char *password) {
    sqlite3_stmt *stmt;
    const char *sql = "SELECT Password FROM Users WHERE Username = ?;";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            const unsigned char *db_password = sqlite3_column_text(stmt, 0);
            if (strcmp(password, (const char*)db_password) == 0) {
                printf("Authenticated successfully\n");
                sqlite3_finalize(stmt);
                return 1;
            }
        }
        sqlite3_finalize(stmt);
    } else {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
    }
    return 0;
}


int user_id_callback(void *data, int argc, char **argv, char **azColName) {
    if (argc == 1) {
        *(int*)data = atoi(argv[0]);
    }
    return 0;
}

int get_user_id(sqlite3 *db, const char *username) {
    sqlite3_stmt *stmt;
    const char *sql = "SELECT UserID FROM Users WHERE Username = ?;";
    int user_id = -1;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            user_id = sqlite3_column_int(stmt, 0);
        }
        sqlite3_finalize(stmt);
    } else {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
    }
    return user_id;
}

void add_memo(sqlite3 *db, int userid, const char *message) {
    sqlite3_stmt *stmt;
    const char *sql = "INSERT INTO Memos (UserID, Message) VALUES (?, ?);";

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_int(stmt, 1, userid);
        sqlite3_bind_text(stmt, 2, message, -1, SQLITE_STATIC);

        if (sqlite3_step(stmt) != SQLITE_DONE) {
            fprintf(stderr, "Failed to add memo: %s\n", sqlite3_errmsg(db));
        } else {
            printf("Memo added successfully\n");
        }
        sqlite3_finalize(stmt);
    } else {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
    }
}

int view_memo_callback(void *NotUsed, int argc, char **argv, char **azColName) {
    for (int i = 0; i < argc; i++) {
        printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
    }
    printf("\n");
    return 0;
}

void view_memos(sqlite3 *db, int userid) {
    char *sql;
    asprintf(&sql, "SELECT MemoID, Message FROM Memos WHERE UserID = %d;", userid);

    if (sqlite3_exec(db, sql, view_memo_callback, 0, NULL) != SQLITE_OK) {
        fprintf(stderr, "Failed to fetch memos\n");
    }

    free(sql);
}

void remove_memo(sqlite3 *db, int memo_id) {
    sqlite3_stmt *stmt;
    const char *sql = "DELETE FROM Memos WHERE MemoID = ?;";

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_int(stmt, 1, memo_id);

        if (sqlite3_step(stmt) != SQLITE_DONE) {
            fprintf(stderr, "Failed to delete memo: %s\n", sqlite3_errmsg(db));
        } else {
            printf("Memo removed successfully\n");
        }
        sqlite3_finalize(stmt);
    } else {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
    }
}

int main() {
    sqlite3 *db;
    char *err_msg = 0;

    int rc = sqlite3_open("project.db", &db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return 1;
    }

    create_tables(db);

    char option[20];
    while (1) {
        printf("Choose an option: register, login, exit: ");
        scanf("%19s", option);

        if (strcmp(option, "register") == 0) {
            char username[50], password[50];
            printf("Enter new username: ");
            scanf("%49s", username);
            printf("Enter new password: ");
            scanf("%49s", password);

            register_user(db, username, password);

        } else if (strcmp(option, "login") == 0) {
            char username[50], password[50];
            printf("Enter username: ");
            scanf("%49s", username);
            printf("Enter password: ");
            scanf("%49s", password);

            if (authenticate(db, username, password)) {
                int userid = get_user_id(db, username);
                printf("Login successful!\n");

                while (1) {
                    printf("Choose an option: add_memo, view_memos, remove_memo, logout: ");
                    char memo_option[20];
                    scanf("%19s", memo_option);

                    if (strcmp(memo_option, "add_memo") == 0) {
                        char memo[256];
                        printf("Enter your memo: ");
                        scanf(" %[^\n]", memo);
                        add_memo(db, userid, memo);

                    } else if (strcmp(memo_option, "view_memos") == 0) {
                        view_memos(db, userid);

                    } else if (strcmp(memo_option, "remove_memo") == 0) {
                        int memo_id;
                        printf("Enter the ID of the memo to remove: ");
                        scanf("%d", &memo_id);
                        remove_memo(db, memo_id);

                    } else if (strcmp(memo_option, "logout") == 0) {
                        break;
                    }
                }
            } else {
                printf("Login failed. Please try again.\n");
            }

        } else if (strcmp(option, "exit") == 0) {
            break;
        }
    }

    sqlite3_close(db);
    return 0;
}