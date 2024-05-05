#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

void generate_rsa_key(const char *private_key_path, const char *public_key_path) {
    RSA *rsa = RSA_new();
    FILE *private_key_file = fopen(private_key_path, "rb");
    FILE *public_key_file = fopen(public_key_path, "rb");

    // Check if key files already exist
    if (private_key_file && public_key_file) {
        fclose(private_key_file);
        fclose(public_key_file);
        RSA_free(rsa);
        return;
    }

    // Generate RSA key pair
    if (!RSA_generate_key_ex(rsa, 2048, BN_new(), NULL)) {
        fprintf(stderr, "Error: Unable to generate RSA key pair.\n");
        ERR_print_errors_fp(stderr);
        RSA_free(rsa);
        exit(EXIT_FAILURE);
    }

    // Set the public exponent value
    if (!RSA_set0_key(rsa, RSA_get0_n(rsa), RSA_get0_e(rsa), NULL)) {
        fprintf(stderr, "Error: Unable to set public exponent.\n");
        ERR_print_errors_fp(stderr);
        RSA_free(rsa);
        exit(EXIT_FAILURE);
    }

    // Write private key to file
    private_key_file = fopen(private_key_path, "wb");
    if (!private_key_file || !PEM_write_RSAPrivateKey(private_key_file, rsa, NULL, NULL, 0, NULL, NULL)) {
        fprintf(stderr, "Error: Unable to write private key to file '%s'.\n", private_key_path);
        RSA_free(rsa);
        exit(EXIT_FAILURE);
    }
    fclose(private_key_file);

    // Write public key to file
    public_key_file = fopen(public_key_path, "wb");
    if (!public_key_file || !PEM_write_RSAPublicKey(public_key_file, rsa)) {
        fprintf(stderr, "Error: Unable to write public key to file '%s'.\n", public_key_path);
        RSA_free(rsa);
        exit(EXIT_FAILURE);
    }
    fclose(public_key_file);

    printf("RSA key pair generated successfully.\n");

    RSA_free(rsa);
}

void create_tables(sqlite3 *db) {
    char *err_msg = 0;
    const char *sql =
            "CREATE TABLE IF NOT EXISTS Users ("
            "UserID INTEGER PRIMARY KEY, "
            "Username TEXT NOT NULL, "
            "Password TEXT NOT NULL);"
            "CREATE TABLE IF NOT EXISTS Memos ("
            "MemoID INTEGER PRIMARY KEY, "
            "UserID INTEGER, "
            "Message TEXT, "
            "FOREIGN KEY(UserID) REFERENCES Users(UserID));";
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

void encrypt_rsa(const char *public_key_path, const char *plain_text, char *encrypted_text) {
    FILE *pub_key_file = fopen(public_key_path, "rb");
    if (!pub_key_file) {
        fprintf(stderr, "Unable to open public key file\n");
        return;
    }

    RSA *rsa = PEM_read_RSA_PUBKEY(pub_key_file, NULL, NULL, NULL);
    fclose(pub_key_file);

    if (!rsa) {
        fprintf(stderr, "Unable to read public key\n");
        return;
    }

    int result = RSA_public_encrypt(strlen(plain_text), (unsigned char*)plain_text, (unsigned char*)encrypted_text, rsa, RSA_PKCS1_PADDING);

    RSA_free(rsa);

    if (result == -1) {
        fprintf(stderr, "Encryption failed\n");
    }
}


void add_memo(sqlite3 *db, int user_id, const char *message) {
    char *err_msg = 0;
    char encrypted_message[256];

    encrypt_rsa("public_key.pem", message, encrypted_message);

    char sql[1024];
    sprintf(sql, "INSERT INTO Memos (UserID, Message) VALUES (%d, '%s');", user_id, encrypted_message);

    if (sqlite3_exec(db, sql, 0, 0, &err_msg) != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", err_msg);
        sqlite3_free(err_msg);
    } else {
        fprintf(stdout, "Memo added successfully\n");
    }
}

void decrypt_rsa(const char *private_key_path, const char *encrypted_text, char *decrypted_text) {
    FILE *priv_key_file = fopen(private_key_path, "rb");
    if (!priv_key_file) {
        fprintf(stderr, "Unable to open private key file\n");
        return;
    }

    RSA *rsa = PEM_read_RSAPrivateKey(priv_key_file, NULL, NULL, NULL);
    fclose(priv_key_file);

    if (!rsa) {
        fprintf(stderr, "Unable to read private key\n");
        return;
    }

    int result = RSA_private_decrypt(RSA_size(rsa), (unsigned char*)encrypted_text, (unsigned char*)decrypted_text, rsa, RSA_PKCS1_PADDING);

    RSA_free(rsa);

    if (result == -1) {
        fprintf(stderr, "Decryption failed\n");
    } else {
        decrypted_text[result] = '\0';
    }
}

void view_memos(sqlite3 *db, int user_id) {
    sqlite3_stmt *stmt;
    const char *sql = "SELECT MemoID, Message FROM Memos WHERE UserID = ?;";

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        return;
    }

    sqlite3_bind_int(stmt, 1, user_id);

    char decrypted_memo[256];

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char *encrypted_memo = (const char*)sqlite3_column_text(stmt, 1);

        decrypt_rsa("private_key.pem", encrypted_memo, decrypted_memo);

        printf("Memo: %s\n", decrypted_memo);
    }

    sqlite3_finalize(stmt);
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

    int rc = sqlite3_open("main.db", &db);
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