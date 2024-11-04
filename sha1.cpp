/*
 * SHA-1 Implementation in C++
 * Author: Tianyi Li
 * Date: 2022.06.22
 * 
 * Description:
 * This program implements the SHA-1 hashing algorithm, which produces a
 * 160-bit hash value from a given input string.
 */

#include <iostream>
#include <array>
#include <string>
#include <cstring>

using namespace std;

// Function declarations
long long ROLT(long long value, int bits);
long long f(long long B, long long C, long long D, int t);
long long K(int t);
string HexToString(long long value, int len);
string SHA_1(const string& input);

// Rotate left operation
long long ROLT(long long value, int bits) {
    return ((value << bits) | (value >> (32 - bits))) & 0xFFFFFFFF;
}

// Function for calculating SHA-1 constant K
long long K(int t) {
    if (t <= 19) return 0x5A827999;
    if (t <= 39) return 0x6ED9EBA1;
    if (t <= 59) return 0x8F1BBCDC;
    if (t <= 79) return 0xCA62C1D6;
    return 0;
}

// Function for calculating the SHA-1 hash
long long f(long long B, long long C, long long D, int t) {
    if (t < 20) {
        return (B & C) | (~B & D);
    }
    if (t < 40) {
        return B ^ C ^ D;
    }
    if (t < 60) {
        return (B & C) | (B & D) | (C & D);
    }
    return B ^ C ^ D;
}

// Convert long long to hexadecimal string
string HexToString(long long value, int len) {
    string result;
    for (int i = 0; i < len; ++i) {
        result += "0123456789ABCDEF"[((value >> ((len - 1 - i) * 4)) & 0xF)];
    }
    return result;
}

// Main SHA-1 function
string SHA_1(const string& input) {
    const int H_SIZE = 5;
    array<long long, H_SIZE> H = {
        0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0
    };

    string padded = input;
    size_t original_length = padded.size() * 8;

    // Padding the input
    padded += '\x80';
    while ((padded.size() * 8) % 512 != 448) {
        padded += '\0';
    }

    // Append the length of the original message
    for (int i = 0; i < 8; ++i) {
        padded += (original_length >> (56 - i * 8)) & 0xFF;
    }

    // Process the padded input in 512-bit chunks
    for (size_t i = 0; i < padded.size(); i += 64) {
        array<long long, 80> W;
        for (int j = 0; j < 16; ++j) {
            W[j] = (static_cast<unsigned char>(padded[i + j * 4]) << 24) |
                   (static_cast<unsigned char>(padded[i + j * 4 + 1]) << 16) |
                   (static_cast<unsigned char>(padded[i + j * 4 + 2]) << 8) |
                   (static_cast<unsigned char>(padded[i + j * 4 + 3]));
        }

        for (int j = 16; j < 80; ++j) {
            W[j] = ROLT(W[j - 3] ^ W[j - 8] ^ W[j - 14] ^ W[j - 16], 1);
        }

        long long A = H[0];
        long long B = H[1];
        long long C = H[2];
        long long D = H[3];
        long long E = H[4];

        for (int j = 0; j < 80; ++j) {
            long long temp = (ROLT(A, 5) + f(B, C, D, j) + E + W[j] + K(j)) & 0xFFFFFFFF;
            E = D;
            D = C;
            C = ROLT(B, 30);
            B = A;
            A = temp;
        }

        // Add the compressed chunk to the current hash value
        H[0] = (H[0] + A) & 0xFFFFFFFF;
        H[1] = (H[1] + B) & 0xFFFFFFFF;
        H[2] = (H[2] + C) & 0xFFFFFFFF;
        H[3] = (H[3] + D) & 0xFFFFFFFF;
        H[4] = (H[4] + E) & 0xFFFFFFFF;
    }

    // Produce the final hash value
    string hash;
    for (const auto& value : H) {
        hash += HexToString(value, 8);
    }
    return hash;
}

// Example usage
int main() {
    string input;
    cout << "Enter a string to hash: ";
    getline(cin, input);
    
    string hash = SHA_1(input);
    cout << "SHA-1 hash: " << hash << endl;
    return 0;
}