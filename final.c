#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sqlite3.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

void generate_rsa_key(const char *private_key_path, const char *public_key_path) {
    RSA *rsa = RSA_new();
    FILE *private_key_file = fopen(private_key_path, "rb");
    FILE *public_key_file = fopen(public_key_path, "rb");

    if (private_key_file && public_key_file) {
        fclose(private_key_file);
        fclose(public_key_file);
        RSA_free(rsa);
        return;
    }

    if (!RSA_generate_key_ex(rsa, 2048, BN_new(), NULL)) {
        fprintf(stderr, "Error: Unable to generate RSA key pair.\n");
        ERR_print_errors_fp(stderr);
        RSA_free(rsa);
        exit(EXIT_FAILURE);
    }

    if (!RSA_set0_key(rsa, RSA_get0_n(rsa), RSA_get0_e(rsa), NULL)) {
        fprintf(stderr, "Error: Unable to set public exponent.\n");
        ERR_print_errors_fp(stderr);
        RSA_free(rsa);
        exit(EXIT_FAILURE);
    }

    private_key_file = fopen(private_key_path, "wb");
    if (!private_key_file || !PEM_write_RSAPrivateKey(private_key_file, rsa, NULL, NULL, 0, NULL, NULL)) {
        fprintf(stderr, "Error: Unable to write private key to file '%s'.\n", private_key_path);
        RSA_free(rsa);
        exit(EXIT_FAILURE);
    }
    fclose(private_key_file);
    
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

bool user_exists(sqlite3 *db, const char *username) {
    sqlite3_stmt *stmt;
    const char *sql = "SELECT COUNT(*) FROM Users WHERE Username = ?";
    int result = 0;

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
	sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
	if (sqlite3_step(stmt) == SQLITE_ROW) {
	    result = sqlite3_column_int(stmt, 0);
	}
	sqlite3_finalize(stmt);
    } else {
	fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
    }
    return result > 0;
}
void register_user(sqlite3 *db, const char *username, const char *password) {
    if (user_exists(db, username)) {
	printf("User already exists!\n");
	return;
    }

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

void encrypt_rsa(const char *public_key_path, const char *plain_text, unsigned char **encrypted_text, int *encrypted_len) {
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

    int rsa_size = RSA_size(rsa);
    *encrypted_text = (unsigned char *)malloc(rsa_size);
    if (!*encrypted_text) {
        fprintf(stderr, "Memory allocation failed\n");
        RSA_free(rsa);
        return;
    }

    *encrypted_len = RSA_public_encrypt(strlen(plain_text), (unsigned char*)plain_text, *encrypted_text, rsa, RSA_PKCS1_PADDING);

    RSA_free(rsa);

    if (*encrypted_len == -1) {
        fprintf(stderr, "Encryption failed\n");
        free(*encrypted_text);
        *encrypted_text = NULL;
    }
}


void add_memo(sqlite3 *db, int user_id, const char *message) {
    char *err_msg = 0;
    unsigned char *encrypted_message = NULL;
    int encrypted_len = 0;

    encrypt_rsa("public_key.pem", message, &encrypted_message, &encrypted_len);

    if (encrypted_message) {
        char sql[1024];
        snprintf(sql, sizeof(sql), "INSERT INTO Memos (UserID, Message) VALUES (%d, ?);", user_id);

        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_blob(stmt, 1, encrypted_message, encrypted_len, SQLITE_TRANSIENT);

            if (sqlite3_step(stmt) != SQLITE_DONE) {
                fprintf(stderr, "Failed to add memo: %s\n", sqlite3_errmsg(db));
            } else {
                fprintf(stdout, "Memo added successfully\n");
            }
            sqlite3_finalize(stmt);
        } else {
            fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        }

        free(encrypted_message);
    }
}

void decrypt_rsa(const char *private_key_path, const unsigned char *encrypted_text, int encrypted_len, unsigned char **decrypted_text) {
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

    int rsa_size = RSA_size(rsa);
    *decrypted_text = (unsigned char *)malloc(rsa_size);
    if (!*decrypted_text) {
        fprintf(stderr, "Memory allocation failed\n");
        RSA_free(rsa);
        return;
    }

    int result = RSA_private_decrypt(encrypted_len, encrypted_text, *decrypted_text, rsa, RSA_PKCS1_PADDING);

    RSA_free(rsa);

    if (result == -1) {
        fprintf(stderr, "Decryption failed\n");
        free(*decrypted_text);
        *decrypted_text = NULL;
    } else {
        (*decrypted_text)[result] = '\0';
    }
}

void view_encrypted_memos(sqlite3 *db, int user_id) {
    sqlite3_stmt *stmt;
    const char *sql = "SELECT MemoID, Message FROM Memos WHERE UserID = ?;";

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        return;
    }

    sqlite3_bind_int(stmt, 1, user_id);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        int memo_id = sqlite3_column_int(stmt, 0);
        const void *encrypted_memo = sqlite3_column_blob(stmt, 1);
        int encrypted_len = sqlite3_column_bytes(stmt, 1);

        printf("Memo ID: %d, Encrypted Content: ", memo_id);
        for (int i = 0; i < encrypted_len; i++) {
            printf("%02X", ((unsigned char*)encrypted_memo)[i]);
        }
        printf("\n");
    }

    sqlite3_finalize(stmt);
}

void view_decrypted_memos(sqlite3 *db, int user_id) {
    sqlite3_stmt *stmt;
    const char *sql = "SELECT MemoID, Message FROM Memos WHERE UserID = ?;";

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        return;
    }

    sqlite3_bind_int(stmt, 1, user_id);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        int memo_id = sqlite3_column_int(stmt, 0);
        const void *encrypted_memo = sqlite3_column_blob(stmt, 1);
        int encrypted_len = sqlite3_column_bytes(stmt, 1);

        unsigned char *decrypted_memo = NULL;
        decrypt_rsa("private_key.pem", encrypted_memo, encrypted_len, &decrypted_memo);

        if (decrypted_memo) {
            printf("Memo ID: %d, Decrypted Content: %s\n", memo_id, decrypted_memo);
            free(decrypted_memo);
        }
    }

    sqlite3_finalize(stmt);
}

void remove_memo(sqlite3 *db, int user_id, int memo_id) {
    sqlite3_stmt *stmt;
    const char *sql = "DELETE FROM Memos WHERE MemoID = ? AND UserID = ?;";
    int rc = sqlite3_prepare_v2(db,sql,-1,&stmt,NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
	return;
    }

    sqlite3_bind_int(stmt, 1, memo_id);
    sqlite3_bind_int(stmt, 2, user_id);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
            fprintf(stderr, "Failed to delete memo: %s\n", sqlite3_errmsg(db));
    } else {
        if (sqlite3_changes(db)==0){
	    printf("Error: Message does not exist or Memo doesn't belong to you.\n");
	} else { 
            printf("Memo removed successfully\n");
        }
        
	sqlite3_finalize(stmt);
    }
}

int main() {
    sqlite3 *db;
    char *err_msg = 0;
    //int userid = get_user_id(db,username);

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
                printf("Login successful!\n");
		int userid = get_user_id(db,username);
                while (1) {
                    int choice;
                    printf("\nChoose an option:\n");
                    printf("1. add_memo\n");
                    printf("2. view_encrypted_memos\n");
                    printf("3. view_decrypted_memos\n");
                    printf("4. remove_memo\n");
                    printf("5. logout\n");
                    printf("Enter your choice: ");
                    scanf("%d*c", &choice);

                    switch (choice) {
                        case 1: {
                            char memo[256];
                            printf("Enter your memo: ");
                            scanf(" %[^\n]%*c", memo);
                            add_memo(db, userid, memo);
                            break;
                        }
                        case 2:
                            view_encrypted_memos(db, userid);
                            break;
                        case 3:
                            view_decrypted_memos(db, userid);
                            break;
                        case 4: {
                            int memo_id;
                            printf("Enter the ID of the memo to remove: ");
                            scanf("%d%*c", &memo_id);
                            remove_memo(db, userid, memo_id);
                            break;
                        }
                        case 5:
                            printf("Logging out...\n");
                            goto logout;
                        default:
                            printf("Invalid choice. Please try again.\n");
                            break;
                    }
                }
                logout:
            }
            else {
                printf("Login failed. Please try again.\n");
            }

        } else if (strcmp(option, "exit") == 0) {
            break;
        }
    }

    sqlite3_close(db);
    return 0;
}
