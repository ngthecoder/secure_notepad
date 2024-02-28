#include <stdio.h>


int check_prime(){ //Checks if a number is prime
	return 0; //if prime
	return 1; //if not prime
}

int get_pq(int p, int q){
	/*
	1. Generate random numbers, from 0~1000
	2. Check if those numbers are prime
	3. Loop 1 and 2, add condition so both are different
	4. Return p and q
	*/
}

int get_n_phin(int p, int q, int n, int phin){
	/*
	1. Calculate n = (p*q)
	2. Calculate phi(n) = (p-1)*((q-1)
	3. Return n and phi(n)
	*/
}

int prime_factors(){
	/*
	1. Get an integer
	2. Find the prime factors
	3. Return the prime factors if it has any	
	*/
}

int check_prime_factors(){
	/*
	1. Gets the result of the prime factors
	2. Check conditions
	- They cannot be the same
	- 1 < (e and d) < phi(n)
	- relatively prime to e, d, and n
	3. If it meets all of them, return pair
	4. If not, nothing
	*/
	
}

int get_ed(int phin, int temp){
	/*
	1. temp = phi(n) * range(0~1000) + 1
	2. Find Prime Factors of temp 
	- prime_factors()
	3. Pick a random pair of prime factors
	- Should store all pairs in an array from check_prime_factors()
	- Pick 1 randomly
	4. Return public and private key pair
	
	*/
}

int encode(){

}

int decode(){
	
	
}