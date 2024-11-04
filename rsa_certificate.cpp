/*
 * RSA Certificate Generation and Verification in C++
 * Author: Tianyi Li
 * Date: 2022.06.23
 * 
 * Description:
 * This program implements RSA key generation, certificate generation, 
 * and verification using the NTL library for big integer operations.
 */

#include <iostream>
#include <fstream>
#include <NTL/ZZ.h>
#include <vector>
#include <cmath>

using namespace std;
using namespace NTL;

#pragma comment(lib, "NTL.lib")

const ZZ ID_TA(123456); // Trusted Authority ID

// Function to generate RSA keys
void RSA_Key(ZZ& p, ZZ& q, ZZ& n, ZZ& e, ZZ& d) {
    ZZ euler;  // n = p * q, euler = (p - 1) * (q - 1)
    int bits;  // Length of random prime bits
    bool choice;

    cout << "Select the length of random primes:" << endl;
    cout << "0. 512 bits" << endl;
    cout << "1. 1024 bits" << endl;
    cin >> choice;
    bits = choice ? 1024 : 512;

    RandomPrime(p, bits, 50);
    RandomPrime(q, bits, 50);

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

// Function to generate certificate using the Chinese Remainder Theorem
void getCRT(const ZZ& e, const ZZ& n, const ZZ& sig_TA, const ZZ& n_TA, const ZZ& ID, const ZZ& ID_TA, const string& name) {
    // Combine ID and public key
    ZZ ID_and_key = ID * power(10, NumBits(e) + 1) + e;

    // Alice's certificate signature
    ZZ s = PowerMod(ID_and_key, sig_TA, n_TA);

    ofstream out("CRT_" + name + ".txt", ios::out | ios::binary);
    // Write certificate information
    out << ID << endl;
    out << e << endl;
    out << n << endl;
    out << s << endl;
    out << ID_TA << endl;
    out << NumBits(e) << endl;
}

// Function to verify the certificate
void verCRT(const ZZ& e_TA, const ZZ& n_TA, const string& file) {
    ifstream in(file);
    
    // Read certificate information
    ZZ signature, e, n, ID;
    in >> ID >> e >> n >> signature;

    // Combine ID and Alice's public key
    ZZ ID_and_key = ID * power(10, NumBits(e) + 1) + e;

    if (PowerMod(signature, e_TA, n_TA) == ID_and_key)
        cout << "Certificate is valid." << endl;
    else
        cout << "Certificate is invalid." << endl;
}

// Main function
int main() {
    ZZ ID_Alice;
    cout << "Enter your ID:" << endl;
    cin >> ID_Alice;

    // RSA key generation for Alice
    cout << "Generating Alice's keys." << endl;
    ZZ p_Alice, q_Alice, n_Alice, e_Alice, d_Alice;
    RSA_Key(p_Alice, q_Alice, n_Alice, e_Alice, d_Alice);

    // RSA key generation for Trusted Authority (TA)
    cout << "Generating TA's keys." << endl;
    ZZ p, q, n, e, d;
    RSA_Key(p, q, n, e, d);

    getCRT(e_Alice, n_Alice, d, n, ID_Alice, ID_TA, "Alice");

    verCRT(e, n, "CRT_Alice.txt");

    return 0;
}