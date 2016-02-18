# SecComm

This is part of an assignment for CMPT 471 Networking 2 at Simon Fraser University I completed around March 2015.
A secure communication channel that uses Enigma encryption and  Diffie-Hellman key exchange protocol.

Currently,this is only the implementation of an Enigma cypher scheme and decypher scheme based from Alan Turing's rotor machines.
 
Diffie-Hellman protocol implementation may be added..sometime..
 


```bash
$ gcc -std=c99 -W -Wall -pedantic -o cypher EnigmaCypher.c
$ ./cypher 1 "hello world"
===============
Encrypted text

nlqwyj o.iq
==============

==============
Decrypted text

hello world
==============
```


