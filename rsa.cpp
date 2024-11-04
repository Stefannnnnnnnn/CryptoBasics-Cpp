// RSA Encryption and Decryption
// Completed on 2022-06-20
// Author: Tianyi Li
//
// Description:
// This code demonstrates RSA key generation, encryption, and decryption
// with a file-based implementation in C++. It uses the NTL library for
// large integer operations. Users can specify a bit length for RSA keys 
// and select a file to encrypt and decrypt.

#include <iostream>
#include <fstream>
#include <NTL/ZZ.h>
#include <vector>
#include <memory>

using namespace std;
using namespace NTL;
#pragma comment(lib, "NTL.lib")

const int group_size = 10;  // Number of bytes per encryption block

// Generate RSA public and private keys
void RSA_key(ZZ& n, ZZ& e, ZZ& d, int bits = 512) {
    ZZ p, q, euler;

    // Generate two random prime numbers p and q with specified bit length
    RandomPrime(p, bits, 100);
    RandomPrime(q, bits, 100);

    // Calculate n (modulus) and Euler's totient function
    n = p * q;
    euler = (p - 1) * (q - 1);

    // Generate public key (e) and private key (d)
    SetSeed(euler);
    do {
        e = RandomBnd(euler);  // Generate random e
    } while (InvModStatus(d, e, euler));  // Find modular inverse of e (d)

    cout << "Public key:\n" << "n: " << n << "\ne: " << e << endl;
    cout << "Private key:\nd: " << d << endl;
}

// Encrypt or decrypt a block using RSA
ZZ RSA_process_block(const ZZ& block, const ZZ& key, const ZZ& n) {
    return PowerMod(block, key, n);  // Encrypt or decrypt block with RSA
}

// Encrypt file content using RSA and save to an output file
void RSA_encrypt(const ZZ& e, const ZZ& n, const string& input_file, const string& output_file = "cipher.txt") {
    ifstream in(input_file, ios::in | ios::binary);
    ofstream out(output_file, ios::out | ios::binary);
    if (!in || !out) {
        cerr << "Error: Unable to open file for encryption." << endl;
        return;
    }

    vector<unsigned char> buffer(group_size);
    ZZ plain_text, cipher_text;
    int last_group_size;

    // Encrypt each block
    while (in.read(reinterpret_cast<char*>(buffer.data()), group_size) || (last_group_size = in.gcount())) {
        plain_text = ZZFromBytes(buffer.data(), last_group_size);
        cipher_text = RSA_process_block(plain_text, e, n);
        out << cipher_text << endl;
    }

    out << last_group_size << endl;  // Store the size of the last group
    cout << "Encryption complete. Encrypted file: " << output_file << endl;
}

// Decrypt RSA encrypted file content and save to an output file
void RSA_decrypt(const ZZ& d, const ZZ& n, const string& input_file, const string& output_file) {
    ifstream in(input_file, ios::in | ios::binary);
    ofstream out(output_file, ios::out | ios::binary);
    if (!in || !out) {
        cerr << "Error: Unable to open file for decryption." << endl;
        return;
    }

    ZZ cipher_text, plain_text;
    vector<unsigned char> buffer(group_size);
    int last_group_size = group_size;

    // Decrypt each block
    while (in >> cipher_text) {
        plain_text = RSA_process_block(cipher_text, d, n);

        int current_pos = in.tellg();
        in.seekg(0, ios::end);
        int end_pos = in.tellg();

        if (current_pos + 10 > end_pos) {  // Handle last block
            in.seekg(current_pos, ios::beg);
            in >> last_group_size;
        }

        BytesFromZZ(buffer.data(), plain_text, last_group_size);
        out.write(reinterpret_cast<char*>(buffer.data()), last_group_size);
    }

    cout << "Decryption complete. Decrypted file: " << output_file << endl;
}

int main() {
    ZZ n, e, d;
    string file;

    // Generate RSA keys with user-defined bit length
    int choice;
    cout << "Select bit length for RSA primes:\n0. 512 bits\n1. 1024 bits" << endl;
    cin >> choice;
    RSA_key(n, e, d, choice ? 1024 : 512);

    // Prompt user for file name and handle encryption and decryption
    cout << "\nEnter the file to encrypt:" << endl;
    cin >> file;
    RSA_encrypt(e, n, file);

    string decrypted_file = "(decrypted)" + file;
    RSA_decrypt(d, n, "cipher.txt", decrypted_file);

    return 0;
}