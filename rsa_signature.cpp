/*
 * RSA Signature Implementation in C++
 * Author: Tianyi Li
 * Date: 2022.06.22
 * 
 * Description:
 * This program implements RSA signature generation and verification
 * using NTL library for big integer operations and SHA-1 for hashing.
 */

#include <iostream>
#include <fstream>
#include <sstream>
#include <NTL/ZZ.h>
#include <vector>
#include "SHA-1.h"

using namespace std;
using namespace NTL;

#pragma comment(lib, "NTL.lib")

// Function to generate RSA keys
void RSA_Key(ZZ& p, ZZ& q, ZZ& n, ZZ& e, ZZ& d) {
    ZZ euler;   // n = p * q, euler = (p - 1) * (q - 1)
    int bits;   // Length of random prime bits
    bool choice;
    
    cout << "Select the length of random primes:" << endl;
    cout << "0. 512 bits" << endl;
    cout << "1. 1024 bits" << endl;
    cin >> choice;
    bits = choice ? 1024 : 512;

    RandomPrime(p, bits, 100);
    RandomPrime(q, bits, 100);

    n = p * q;
    euler = (p - 1) * (q - 1); // Compute n and Euler's totient

    // Key generation
    SetSeed(euler);
    while (true) {
        e = RandomBnd(euler);
        if (!InvModStatus(d, e, euler))
            break;
    }
}

// Function to sign a message
void RSA_sign(const ZZ& e, const ZZ& n, ZZ& msg, ZZ& signature) {
    ifstream in;
    string file;
    string plain_text;
    
    cout << "Enter the filename to sign:" << endl;
    cin >> file;
    
    in.open(file, ios::in | ios::binary);
    if (!in) {
        cerr << "Error opening file." << endl;
        return;
    }

    stringstream buf;
    buf << in.rdbuf();
    plain_text = buf.str();
    in.close();

    string message = SHA_1(plain_text);
    // Convert 40-byte hexadecimal message digest to a big integer
    for (char c : message) {
        msg *= 16;
        msg += (c > '9') ? (c - 'a' + 10) : (c - '0');
    }
    signature = PowerMod(msg, e, n);
    cout << "Signature:" << endl;
    cout << signature << endl << endl;
}

// Function to verify the signature
void RSA_ver(const ZZ& d, const ZZ& n, const ZZ& msg, const ZZ& signature) {
    // Public verification function
    bool ver = PowerMod(signature, d, n) == msg;
    cout << (ver ? "Signature is valid." : "Signature is invalid.") << endl;
}

// Main function
int main() {
    ZZ p, q, n, a, b; // a is the signing private key, b is the verification public key
    ZZ msg(0);
    ZZ signature;

    // RSA key generation
    RSA_Key(p, q, n, a, b);

    // RSA signing
    RSA_sign(a, n, msg, signature);

    // RSA signature verification
    RSA_ver(b, n, msg, signature);

    return 0;
}