#ifndef EN_H
#define EN_H

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#define NUM_SCHEMES 	5
#define NUM_KEYS 	30
#define NUM_ROTORS	2


// Machine state
typedef struct {
	size_t scheme;
	size_t rFast;
	size_t rSlow;
} schemeInfo_t;

int cypher(const int, schemeInfo_t const * const);
int decypher(const int, schemeInfo_t const * const);
void encryption(char str[], size_t scheme, int (*encFunc)(const int, schemeInfo_t const * const));

#endif
