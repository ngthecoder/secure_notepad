#include <stdio.h>
#include <stdlib.h>
#include "RSA_Algorithm.h"  // Include the header file for RSA Algorithm declarations

int main() {
    printf("Welcome to Secure Notepad!\nPlease Log in:\n");

    int option, public_key, private_key, quit;
    quit = 0;

    do {
        menu();  // Call the menu function from RSA_Algorithm.c
        scanf("%d", &option);

        switch (option) {
            case 1:
                create_key_pair(&public_key, &private_key);
                printf("Key Pair Created: Public Key = %d, Private Key = %d\n", public_key, private_key);
                printf("Press any key to continue...");
                getchar(); // Consume the newline character
                getchar(); // Wait for user input
                break;
            case 2:
                printf("Option 2\n");
                break;
            case 3:
                printf("Option 3\n");
                break;
            case 4:
                printf("Option 4\n");
                break;
            case 5:
                printf("Option 5\n");
                break;
            case 6:
                printf("Exiting program.\n");
                quit = 1; // Set quit to 1 to exit the loop
                break;
            default:
                printf("Invalid Input.\n");
        }
    } while (quit ==0);
    return 0;
}