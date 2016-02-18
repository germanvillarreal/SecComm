
/*******************************************************************************
 ** File:       EnigmaCypher.c
 ** Author:     German Villarreal
 ** 
 ** Description
 ** 
 ** This file encapsulates the implementation of an Enigma cypher scheme and 
 ** decypher scheme based from Alan Turing's rotor machines.
 ** 
 ** Diffie-Hellman protocol was used for users to agree on an encryption scheme.
 **
 **
 ** This is part of an assignment for CMPT 471 at Simon Fraser University.
 ** Assignment specified for 5 schemes each with 2 rotors and a predefined set
 ** of 30 allowable characters as private keys.
 **
 **
 ** Date:       March 2015
*******************************************************************************/

#include "EnigmaCypher.h" 


// "Private" Funtcions
int isValid(int);
int toLower(int);
int getDomIdx(int);



/**
 * Quick usage demonstration
*/
int main(int argc, char**argv) {
	size_t scheme;

	if(argc != 3) {
		return -1;
	}

	if(!(scheme = atoi(argv[1]))) {
		return -1;
	}


	encryption(argv[2], scheme, cypher);
	printf("===============\n"
		"Encrypted text\n\n"
		"%s\n"
		"==============\n", argv[2]);

	printf("\n");

	encryption(argv[2], scheme, decypher);
	printf("==============\n"
		"Decrypted text\n\n"
		"%s\n"
		"==============\n", argv[2]);
	
	
	return 0; 
}

int master[NUM_KEYS] =
	{ ',','.',' ','?','a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z' };


//TODO: Generate a scheme using a secret key value, not simply select one of these 5 schemes from the secret key
int s[NUM_SCHEMES][NUM_ROTORS][NUM_KEYS] = {
	{ // Scheme 1
	{ 'q','w','e','r',' ','t','y','u','i','o','p','a','s','d','f','g','h','j','k','l','z','x','c','v','b','n','m','.',',','?' },
	{ 'm','n','b','v','c',' ','x','z','l','k','j','h','g','f','d','s','a','p','o','i','u','.',',','?','y','t','r','e','w','q' }
	},

	{ // Scheme 2
	{ 'a','s',' ','d','f','g','h','j','k','l','m','n','b','v','c','x','z','q','w','e','r','t','y','u','i','o','p',',','?','.' },
	{ 'q','a','z',' ','w','s','x','e','d','c','r','f','v','t','g','b','y','h','n','u','j','m','i','k',',','o','l','.','?','p' }
	},

	{ // Scheme 3
	{ '.',',','?','q','p','w',' ','o','e','i','r','u','t','y','v','c','x','z','b','n','m','h','g','f','d','s','a','j','k','l' },
	{ 'z','x','c','v','b','n','m','a',' ','s','d','f','g','h','j','k','l','p','o','i','u','y','t','r','e','w','q','.',',','?' }
	},
	{ // Scheme 4
	{ 'z','a','q','x','s','w','c','d','e','v','f','r','b','g','t','n','h','y',' ','m','j','u',',','k','i','.','l','o','?','p' },
	{ 'p','o','i','u','y','t','r','e','w','q','a','s','d','f','g','h','j','.',',','?','k','l',' ','m','n','b','v','c','x','z' }
	},
	{ // Scheme 5
	{ 'a','d','g','j','l','m','b','c','z','q','e','t','u','o','p','i','y',' ','r','w','s','f','h','k','n','v','x',',','.','?' },
	{ 'p','i','u','y','t','r','e','w','q','o','a','s','z','x','d','c','f','v','g','b','h','n',' ','j','m','k',',','l','.','?' }
	}
};


/*******************************************************************************
 *  Function: void encryption(char str[], size_t scheme, 
 *                      int (*encFunc)(const int, schemeInfo_t const * const))
 *
 *  Parameters: - char str[]    : the string to be manipulated in place
 *              - size_t scheme : the previously agreed upon scheme to use
 *              - encFunc       : the function for encryption/decryption
 *
 *  Return: char str[] manipulated in place
 *
 *  Description: Main driver to encrypt and decrypt a string. Checks character 
 *               by character, and manipulates the overall state of the
 *               encryption machine.
 *
 */
void encryption(char str[], size_t scheme, 
        int (*encFunc)(const int, schemeInfo_t const * const)) {

	schemeInfo_t si;
//	bzero(&si, sizeof(schemeInfo_t)); strings library for one function? :/
	si.scheme = scheme%NUM_SCHEMES;
	si.rFast = si.rSlow = 0;
	
	for(int i=0; str[i]!='\0'; ++i) {
	
		// Skip this character if not in domain
		if(isValid(str[i])==0) {
			continue; 
		}
		
		// Our keys are lowercase, so convert to lowercase..
		// TODO: recognize upper/lower case
		str[i]=toLower(str[i]);

		// Convert the character to its encrypted/decrypted counterpart
		str[i]=encFunc(str[i], &si);

		// Set up the machine for the next character
		++si.rFast;
		si.rFast = si.rFast%NUM_KEYS;
		if(si.rFast == 0) {
			++si.rSlow;
			si.rSlow = si.rSlow%NUM_ROTORS;
		}
	}	
}


/*******************************************************************************
 *  Function: int cypher(const int c, schemeInfo_t const * const si)
 *
 *  Parameters: - int c         : character to encrypt
 *              - schemeInfo_t  : the overall state of the encryption machine
 *
 *  Return: int : encrypted character
 *
 *  Description: Encrypts a single character.
 *
*/
int cypher(const int c, schemeInfo_t const * const si) {

	// Find the letter's poisiton in our alphabet
	// add to it the adjustment from each fast rotor revolution
	size_t idx=(getDomIdx(c)+si->rFast)%NUM_KEYS;

	// Find the encryption character
	return s[si->scheme][si->rSlow][idx];
}


/*******************************************************************************
 *  Function: int decypher(const int c, schemeInfo_t const * const si)
 *
 *  Parameters: - int c         : character to decrypt
 *              - schemeInfo_t  : the overall state of the encryption machine
 *
 *  Return: int : decrypted character
 *
 *  Description: Decrypts a single character.
 *
*/
int decypher(const int c, schemeInfo_t const * const si) {

	// Find the character in the appropriate encryption scheme si->scheme
	// with appropriate slow rotor placement si->rSlow
	for(int i=0; i<NUM_KEYS; ++i) {
		if(c == s[si->scheme][si->rSlow][(i+si->rFast)%NUM_KEYS]) {
			return master[i];
		}
	}

	// Look for the original characeter in the master mapping set
	// and adjust by the number of fast rotor revolutions
	return -1;
}

////////////////////////////////////////////////////////////////////////////////
//	Helper Functions								                          //	
////////////////////////////////////////////////////////////////////////////////

int isValid(int c) {
	return (('A'<=c && c<='Z') || ('a'<=c && c<='z')
		|| c==' ' || c=='.' || c==',' || c=='?');
}

int getDomIdx(int c) {
	if(isValid(c)) {
		for(size_t i=0; i<NUM_KEYS; i++) {
			if(master[i] == c)
				return (int) i;
		}
	}
	return -1;
}

int toLower(int c) {
	if('A'<=c && c<='Z') {
		return c-'A'+'a';
	}
	return c;
}

