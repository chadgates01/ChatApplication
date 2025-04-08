#include <iostream>
#include <vector>
#include <set>
#include <ctime>
#include <cstdlib>

class ElGamalCrypto
{
private:
    // System parameters
    long long prime;      // Prime modulus p
    long long generator;  // Generator/primitive root α
    long long privateKey; // Private key a
    long long publicKey;  // Public key β = α^a mod p

    // Helper methods
    bool checkPrime(long long num) const
    {
        if (num < 2)
            return false;
        for (long long i = 2; i * i <= num; i++)
        {
            if (num % i == 0)
                return false;
        }
        return true;
    }

    long long modPow(long long base, long long exponent, long long modulus) const
    {
        long long result = 1;
        base = base % modulus;
        while (exponent > 0)
        {
            if (exponent % 2 == 1)
                result = (result * base) % modulus;
            exponent = exponent >> 1;
            base = (base * base) % modulus;
        }
        return result;
    }

    bool checkPrimitiveRoot(long long g, long long p) const
    {
        std::set<long long> uniqueValues;
        for (long long i = 1; i < p; i++)
        {
            uniqueValues.insert(modPow(g, i, p));
        }
        return uniqueValues.size() == p - 1;
    }

    long long generateSecureRandom(long long max) const
    {
        return 1 + rand() % (max - 1);
    }

    // Modular multiplicative inverse
    long long modInverse(long long a, long long m) const
    {
        return modPow(a, m - 2, m);
    }

public:
    // Constructor - initialize with default values
    ElGamalCrypto() : prime(0), generator(0), privateKey(0), publicKey(0)
    {
        std::srand(static_cast<unsigned int>(std::time(nullptr)));
    }

    // Setup system parameters
    bool setupSystem(long long p, long long g, long long privKey)
    {
        std::cout << "\n[System Setup] Validating parameters..." << std::endl;

        // Validate prime
        if (!checkPrime(p))
        {
            std::cout << "  ❌ Error: " << p << " is not a prime number." << std::endl;
            return false;
        }
        std::cout << "  ✓ Prime validation passed." << std::endl;

        // Validate private key
        if (privKey < 1 || privKey >= p - 1)
        {
            std::cout << "  ❌ Error: Private key must be between 1 and " << p - 2 << "." << std::endl;
            return false;
        }
        std::cout << "  ✓ Private key validation passed." << std::endl;

        // Validate generator
        if (!checkPrimitiveRoot(g, p))
        {
            std::cout << "  ❌ Error: " << g << " is not a primitive root modulo " << p << "." << std::endl;
            return false;
        }
        std::cout << "  ✓ Generator validation passed." << std::endl;

        // Set parameters
        prime = p;
        generator = g;
        privateKey = privKey;

        // Generate public key
        publicKey = modPow(generator, privateKey, prime);

        std::cout << "\n[System Setup] Complete! ElGamal cryptosystem is ready." << std::endl;
        return true;
    }

    // Generate keypair
    void generateKeypair()
    {
        publicKey = modPow(generator, privateKey, prime);
    }

    // Display public parameters
    void displayPublicParameters() const
    {
        std::cout << "\n[Public Parameters] 🔑" << std::endl;
        std::cout << "  • Prime (p): " << prime << std::endl;
        std::cout << "  • Generator (α): " << generator << std::endl;
        std::cout << "  • Public Key (β): " << publicKey << std::endl;
    }

    // Encrypt message
    std::pair<long long, long long> encrypt(long long message)
    {
        if (message < 0 || message >= prime)
        {
            std::cout << "  ❌ Error: Message must be between 0 and " << prime - 1 << "." << std::endl;
            return {-1, -1};
        }

        // Generate random k
        long long k = generateSecureRandom(prime - 1);

        // Compute ciphertext components
        long long c1 = modPow(generator, k, prime);
        long long c2 = (message * modPow(publicKey, k, prime)) % prime;

        return {c1, c2};
    }

    // Decrypt ciphertext
    long long decrypt(const std::pair<long long, long long> &ciphertext)
    {
        long long c1 = ciphertext.first;
        long long c2 = ciphertext.second;

        // Calculate shared secret
        long long s = modPow(c1, privateKey, prime);

        // Calculate s^(-1) mod p
        long long sInverse = modInverse(s, prime);

        // Compute message = c2 * s^(-1) mod p
        long long message = (c2 * sInverse) % prime;

        return message;
    }

    // Getters
    long long getPrime() const { return prime; }
    long long getGenerator() const { return generator; }
    long long getPublicKey() const { return publicKey; }
};

int main()
{
    std::cout << "=================================" << std::endl;
    std::cout << "    ElGamal Encryption System    " << std::endl;
    std::cout << "=================================" << std::endl;

    // Create ElGamal system
    ElGamalCrypto elgamal;

    // Get parameters from user
    long long p, g, a;
    long long message;

    std::cout << "\n[Parameter Setup]" << std::endl;
    std::cout << "Enter prime number (p): ";
    std::cin >> p;

    std::cout << "Enter generator value (α): ";
    std::cin >> g;

    std::cout << "Enter private key (a): ";
    std::cin >> a;

    // Setup the system
    if (!elgamal.setupSystem(p, g, a))
    {
        std::cout << "\n❌ System setup failed. Exiting..." << std::endl;
        return 1;
    }

    // Display public parameters
    elgamal.displayPublicParameters();

    // Get message to encrypt
    std::cout << "\n[Encryption]" << std::endl;
    std::cout << "Enter message to encrypt (0 <= m < " << p << "): ";
    std::cin >> message;

    // Encrypt message
    std::pair<long long, long long> ciphertext = elgamal.encrypt(message);
    if (ciphertext.first == -1)
    {
        std::cout << "❌ Encryption failed. Exiting..." << std::endl;
        return 1;
    }

    std::cout << "\n[Encryption Result] 🔒" << std::endl;
    std::cout << "  • Ciphertext (c₁): " << ciphertext.first << std::endl;
    std::cout << "  • Ciphertext (c₂): " << ciphertext.second << std::endl;

    // Decrypt message
    long long decryptedMessage = elgamal.decrypt(ciphertext);

    std::cout << "\n[Decryption Result] 🔓" << std::endl;
    std::cout << "  • Original message: " << message << std::endl;
    std::cout << "  • Decrypted message: " << decryptedMessage << std::endl;

    if (message == decryptedMessage)
    {
        std::cout << "  ✓ Verification successful! Decryption works correctly." << std::endl;
    }
    else
    {
        std::cout << "  ❌ Verification failed! Decryption error occurred." << std::endl;
    }

    std::cout << "\n[Process Complete] ✅" << std::endl;

    return 0;
}