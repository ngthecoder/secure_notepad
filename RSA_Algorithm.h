#ifndef RSA_ALGORITHM_H
#define RSA_ALGORITHM_H

// Function declarations
int check_prime(int n);
int get_pq(int *p, int *q);
int get_n_phin(int p, int q, int *n, int *phin);
int prime_factors(int n);
int check_prime_factors(int e, int d, int n);
void get_ed(int phin, int *e, int *d);
int create_key_pair(int *public_key, int *private_key);
void menu();

#endif

//gcc -c main.c -o main.o
//gcc -c RSA_Algorithm.c -o RSA_Algorithm.o
//gcc main.o RSA_Algorithm.o -o SecureNotepad
