#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#define MAX_STR_LEN 256
#define KEY_SIZE 2048
#define PUBLIC_EXPONENT 65537

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

    if (!RSA_generate_key_ex(rsa, KEY_SIZE, BN_new(), NULL)) {
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

void encrypt_string(const char *plaintext, FILE *output_file, RSA *public_key) {
    int rsa_len = RSA_size(public_key);
    unsigned char *encrypted_text = (unsigned char *)malloc(rsa_len);
    if (!encrypted_text) {
        fprintf(stderr, "Error: Memory allocation failed.\n");
        exit(EXIT_FAILURE);
    }

    int encrypted_len = RSA_public_encrypt(strlen(plaintext) + 1, (const unsigned char *)plaintext, encrypted_text, public_key, RSA_PKCS1_PADDING);
    if (encrypted_len == -1) {
        fprintf(stderr, "Error: Encryption failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        free(encrypted_text);
        exit(EXIT_FAILURE);
    }
    fwrite(encrypted_text, 1, encrypted_len, output_file);
    free(encrypted_text);
}

void decrypt_string(FILE *input_file, const char *private_key_path) {
    RSA *rsa = NULL;
    FILE *private_key_file = fopen(private_key_path, "rb");
    if (!private_key_file) {
        fprintf(stderr, "Error: Unable to open private key file '%s'.\n", private_key_path);
        exit(EXIT_FAILURE);
    }

    rsa = PEM_read_RSAPrivateKey(private_key_file, NULL, NULL, NULL);
    fclose(private_key_file);

    if (!rsa) {
        fprintf(stderr, "Error: Unable to read private key from file '%s': %s\n", private_key_path, ERR_error_string(ERR_get_error(), NULL));
        exit(EXIT_FAILURE);
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
            fprintf(stderr, "Error: Decryption failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
            RSA_free(rsa);
            free(encrypted_text);
            free(decrypted_text);
            exit(EXIT_FAILURE);
        }
        printf("%.*s\n", decrypted_len, decrypted_text);
    }

    free(encrypted_text);
    free(decrypted_text);
    RSA_free(rsa);
}

int main() {
    const char *private_key_path = "private_key.pem";
    const char *public_key_path = "public_key.pem";
    char input[MAX_STR_LEN] = {0};

    RSA *public_key = NULL;
    FILE *public_key_file = fopen(public_key_path, "rb");
    if (public_key_file) {
        public_key = PEM_read_RSA_PUBKEY(public_key_file, NULL, NULL, NULL);
        fclose(public_key_file);
    }

    if (!public_key) {
        fprintf(stderr, "Error: Unable to read public key from file '%s': %s\n", public_key_path, ERR_error_string(ERR_get_error(), NULL));
        generate_rsa_key(private_key_path, public_key_path);
        exit(EXIT_FAILURE);
    }

    printf("Public Key:\n");
    PEM_write_RSA_PUBKEY(stdout, public_key);

    while (1) {
        printf("\nChoose an option:\n1. Encrypt string\n2. Decrypt strings\n3. Display encrypted strings\n4. Exit\n");
        fgets(input, MAX_STR_LEN, stdin);
        input[strcspn(input, "\n")] = '\0';

        if (strcmp(input, "1") == 0) {
            printf("Enter a string: ");
            fgets(input, MAX_STR_LEN, stdin);
            input[strcspn(input, "\n")] = '\0';

            FILE *output_file = fopen("encrypted.txt", "ab");
            if (!output_file) {
                fprintf(stderr, "Error: Unable to open output file.\n");
                RSA_free(public_key);
                return EXIT_FAILURE;
            }
            encrypt_string(input, output_file, public_key);
            fclose(output_file);
        } else if (strcmp(input, "2") == 0) {
            printf("Decrypting strings:\n");
            FILE *input_file = fopen("encrypted.txt", "rb");
            if (!input_file) {
                fprintf(stderr, "Error: Unable to open input file.\n");
                RSA_free(public_key);
                return EXIT_FAILURE;
            }
            decrypt_string(input_file, private_key_path);
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
            break;
        } else {
            printf("Invalid option. Please choose again.\n");
        }
    }

    RSA_free(public_key);
    return 0;
}
