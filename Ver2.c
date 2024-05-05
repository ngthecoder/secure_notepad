#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#define MAX_STR_LEN 256

bool check_keys_exist(const char *public_key_path, const char *private_key_path) {
    FILE *public_key_file = fopen(public_key_path, "rb");
    FILE *private_key_file = fopen(private_key_path, "rb");

    if (public_key_file && private_key_file) {
        fclose(public_key_file);
        fclose(private_key_file);
        return true;
    }

    return false;
}

RSA *load_rsa_key(const char *key_path, bool is_public) {
    RSA *rsa = NULL;
    FILE *key_file = fopen(key_path, "rb");
    if (!key_file) {
        fprintf(stderr, "Error: Unable to open key file '%s'.\n", key_path);
        return NULL;
    }

    if (is_public)
        rsa = PEM_read_RSA_PUBKEY(key_file, NULL, NULL, NULL);
    else
        rsa = PEM_read_RSAPrivateKey(key_file, NULL, NULL, NULL);

    fclose(key_file);

    if (!rsa) {
        fprintf(stderr, "Error: Unable to read %s key from file '%s': %s\n", is_public ? "public" : "private", key_path, ERR_error_string(ERR_get_error(), NULL));
        return NULL;
    }

    return rsa;
}

RSA *generate_rsa_keypair(const char *public_key_path, const char *private_key_path) {
    RSA *rsa = RSA_new();
    BIGNUM *bn = BN_new();

    // Set the public exponent
    if (!BN_set_word(bn, RSA_F4)) {
        fprintf(stderr, "Error: Failed to set public exponent.\n");
        RSA_free(rsa);
        BN_free(bn);
        return NULL;
    }

    // Generate RSA key pair
    if (!RSA_generate_key_ex(rsa, 2048, bn, NULL)) {
        fprintf(stderr, "Error: Failed to generate RSA key pair: %s\n", ERR_error_string(ERR_get_error(), NULL));
        RSA_free(rsa);
        BN_free(bn);
        return NULL;
    }

    // Write private key to file
    FILE *private_key_file = fopen(private_key_path, "wb");
    if (!private_key_file || !PEM_write_RSAPrivateKey(private_key_file, rsa, NULL, NULL, 0, NULL, NULL)) {
        fprintf(stderr, "Error: Failed to write private key to file '%s'.\n", private_key_path);
        RSA_free(rsa);
        BN_free(bn);
        fclose(private_key_file);
        return NULL;
    }
    fclose(private_key_file);

    // Write public key to file
    FILE *public_key_file = fopen(public_key_path, "wb");
    if (!public_key_file || !PEM_write_RSAPublicKey(public_key_file, rsa)) {
        fprintf(stderr, "Error: Failed to write public key to file '%s'.\n", public_key_path);
        RSA_free(rsa);
        BN_free(bn);
        fclose(public_key_file);
        return NULL;
    }
    fclose(public_key_file);

    RSA_free(rsa);
    BN_free(bn);

    return load_rsa_key(public_key_path, true);
}

void encrypt_string(const char *plaintext, FILE *output_file, RSA *rsa) {
    if (!rsa) {
        fprintf(stderr, "Error: Invalid RSA key.\n");
        return;
    }

    int rsa_len = RSA_size(rsa);
    unsigned char *encrypted_text = (unsigned char *)malloc(rsa_len);
    if (!encrypted_text) {
        fprintf(stderr, "Error: Memory allocation failed.\n");
        RSA_free(rsa);
        exit(EXIT_FAILURE);
    }

    int encrypted_len = RSA_public_encrypt(strlen(plaintext), (const unsigned char *)plaintext, encrypted_text, rsa, RSA_PKCS1_PADDING);
    if (encrypted_len == -1) {
        fprintf(stderr, "Error: Encryption failed.\n");
        RSA_free(rsa);
        free(encrypted_text);
        exit(EXIT_FAILURE);
    }
    fwrite(encrypted_text, 1, encrypted_len, output_file);
    free(encrypted_text);
}

void display_strings(FILE *input_file, RSA *rsa) {
    if (!rsa) {
        fprintf(stderr, "Error: Invalid RSA key.\n");
        return;
    }

    int rsa_len = RSA_size(rsa);
    unsigned char *encrypted_text = (unsigned char *)malloc(rsa_len);
    if (!encrypted_text) {
        fprintf(stderr, "Error: Memory allocation failed.\n");
        RSA_free(rsa);
        exit(EXIT_FAILURE);
    }

    unsigned char *decrypted_text = (unsigned char *)malloc(rsa_len);
    if (!decrypted_text) {
        fprintf(stderr, "Error: Memory allocation failed.\n");
        RSA_free(rsa);
        free(encrypted_text);
        exit(EXIT_FAILURE);
    }

    size_t read_bytes;
    while ((read_bytes = fread(encrypted_text, 1, rsa_len, input_file)) > 0) {
        int decrypted_len = RSA_private_decrypt(read_bytes, encrypted_text, decrypted_text, rsa, RSA_PKCS1_PADDING);
        if (decrypted_len == -1) {
            fprintf(stderr, "Error: Decryption failed.\n");
            RSA_free(rsa);
            free(encrypted_text);
            free(decrypted_text);
            exit(EXIT_FAILURE);
        }
        printf("%s\n", decrypted_text);
    }

    free(encrypted_text);
    free(decrypted_text);
    RSA_free(rsa);
}

int main() {
    const char *public_key_path = "public_key.pem";
    const char *private_key_path = "private_key.pem";
    char input[MAX_STR_LEN] = {0};

    RSA *public_key = load_rsa_key(public_key_path, true);
    if (!public_key) {
        printf("Public key not found. Generating RSA key pair...\n");
        public_key = generate_rsa_keypair(public_key_path, private_key_path);
        if (!public_key) {
            fprintf(stderr, "Error: Unable to generate RSA key pair.\n");
            return EXIT_FAILURE;
        }
    } else {
        printf("Public key loaded successfully.\n");
    }

    while (1) {
        printf("\nChoose an option:\n1. Encrypt and store string\n2. Display strings\n3. Display encrypted strings\n4. Exit\n");
        fgets(input, MAX_STR_LEN, stdin);
        input[strcspn(input, "\n")] = '\0'; // Remove newline character

        if (strcmp(input, "1") == 0) {
            printf("Enter a string: ");
            fgets(input, MAX_STR_LEN, stdin);
            input[strcspn(input, "\n")] = '\0'; // Remove newline character

            FILE *output_file = fopen("encrypted.txt", "ab");
            if (!output_file) {
                fprintf(stderr, "Error: Unable to open output file.\n");
                RSA_free(public_key);
                return EXIT_FAILURE;
            }
            encrypt_string(input, output_file, public_key);
            fclose(output_file);
        } else if (strcmp(input, "2") == 0) {
            printf("Displaying strings:\n");
            FILE *input_file = fopen("encrypted.txt", "rb");
            if (!input_file) {
                fprintf(stderr, "Error: Unable to open input file.\n");
                RSA_free(public_key);
                return EXIT_FAILURE;
            }
            display_strings(input_file, public_key);
            fclose(input_file);
        } else if (strcmp(input, "3") == 0) {
            printf("Displaying encrypted strings:\n");
            FILE *input_file = fopen("encrypted.txt", "rb");
            if (!input_file) {
                fprintf(stderr, "Error: Unable to open input file.\n");
                RSA_free(public_key);
                return EXIT_FAILURE;
            }

            int ch;
            while ((ch = fgetc(input_file)) != EOF) {
                printf("%02X ", ch);
            }
            fclose(input_file);
        } else if (strcmp(input, "4") == 0) {
            printf("Exiting...\n");
            RSA_free(public_key);
            break;
        } else {
            printf("Invalid option. Please choose again.\n");
        }
    }

    return EXIT_SUCCESS;
}
