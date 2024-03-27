#include <stdio.h>
#include <stdlib.h>
#include "RSA_Algorithm.h"

int check_prime(int n) {
	printf("Completing step 1...\n");
    if (n <= 1)
        return 0; // Not a prime number
    for (int i = 2; i * i <= n; ++i) {
        if (n % i == 0)
            return 0; // Not a prime number
    }
    return 1; // Prime number
}

int get_pq(int *p, int *q) {
	printf("Completing step 2...\n");
    do {
        *p = rand() % 1000 + 1;
    } while (!check_prime(*p));

    do {
        *q = rand() % 1000 + 1;
    } while (!check_prime(*q) || *p == *q);

    return 0;
}

int get_n_phin(int p, int q, int *n, int *phin)
{    printf("Completing step 3...\n"); 
    *n = p * q;
    *phin = (p - 1) * (q - 1);
    return 0;
}

int prime_factors(int n) {
	printf("Completing Step 4...\n");
    printf("Prime factors of %d: \n", n);
    
    for (int i = 2; i <= n; ++i) {
        while (n % i == 0) {
            printf("%d ", i);
            n /= i;
        }
    }

    printf("\n");
    return 0;
}

int check_prime_factors(int e, int d, int n) {
    if (e == d || e <= 1 || d <= 1 || e >= n || d >= n)
        return 0; // Invalid keys
    for (int i = 2; i <= e && i <= d; ++i) {
        if (e % i == 0 && d % i == 0)
            return 0; // Not relatively prime
    }
    return 1; // Valid keys
}

void get_ed(int phin, int *e, int *d) {
    do {
        *e = rand() % phin + 1;
    } while (!check_prime(*e) || !check_prime_factors(*e, phin, phin));
    
    *d = 1;
    while ((*e * *d) % phin != 1) {
        (*d)++;
    }
}

int create_key_pair(int *public_key, int *private_key) {
    int p, q, n, phin;
    get_pq(&p, &q);
    get_n_phin(p, q, &n, &phin);
    get_ed(phin, public_key, private_key);
    return 0;
}

void menu() {
    printf("Choose an option: \n");
    printf("1. Create new key pair\n");
    printf("2. View your key\n");
    printf("3. Create a message\n");
    printf("4. View your unencrypted message\n");
    printf("5. Delete your message\n");
    printf("6. Exit\n");
}
