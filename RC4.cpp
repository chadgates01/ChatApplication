#include <iostream>
#include <vector>
#include <string>
#include <iomanip>

class RC4Cipher
{
private:
    std::vector<int> sBox;
    std::vector<int> keyBytes;
    std::vector<int> keyStream;

    void initSBox()
    {
        sBox.resize(256);
        for (int i = 0; i < 256; i++)
        {
            sBox[i] = i;
        }
    }

    void keyScheduling()
    {
        int j = 0;
        int keyLength = keyBytes.size();

        for (int i = 0; i < 256; i++)
        {
            j = (j + sBox[i] + keyBytes[i % keyLength]) % 256;
            std::swap(sBox[i], sBox[j]);
        }
    }

    void generateKeyStream(int length)
    {
        keyStream.clear();
        keyStream.resize(length);

        int i = 0;
        int j = 0;

        for (int k = 0; k < length; k++)
        {
            i = (i + 1) % 256;
            j = (j + sBox[i]) % 256;

            std::swap(sBox[i], sBox[j]);

            int t = (sBox[i] + sBox[j]) % 256;
            keyStream[k] = sBox[t];
        }
    }

public:
    RC4Cipher()
    {
        initSBox();
    }

    RC4Cipher(const std::vector<int> &key)
    {
        setKey(key);
    }

    void setKey(const std::vector<int> &key)
    {
        keyBytes = key;

        initSBox();
        keyScheduling();

        std::cout << " Key set successfully. RC4 is ready for encryption/decryption." << std::endl;
    }

    std::vector<int> process(const std::vector<int> &data)
    {
        std::vector<int> workingSBox = sBox;

        std::vector<int> result(data.size());
        int i = 0;
        int j = 0;

        for (size_t k = 0; k < data.size(); k++)
        {
            i = (i + 1) % 256;
            j = (j + workingSBox[i]) % 256;

            std::swap(workingSBox[i], workingSBox[j]);

            int t = (workingSBox[i] + workingSBox[j]) % 256;
            int keystreamByte = workingSBox[t];

            result[k] = data[k] ^ keystreamByte;
        }

        return result;
    }

    void printKeyStream(int length)
    {
        generateKeyStream(length);

        std::cout << "Key Stream Bytes: ";
        for (int i = 0; i < length && i < keyStream.size(); i++)
        {
            std::cout << std::setw(2) << std::hex << keyStream[i] << " ";
        }
        std::cout << std::dec << std::endl;
    }

    static void displayBytes(const std::vector<int> &bytes, const std::string &label)
    {
        std::cout << label << std::endl;

        const int bytesPerRow = 16;

        for (size_t i = 0; i < bytes.size(); i++)
        {
            if (i % bytesPerRow == 0 && i > 0)
                std::cout << std::endl;
            std::cout << std::setw(3) << bytes[i] << " ";
        }
        std::cout << std::endl;
    }
};

int main()
{
    std::cout << "=================================" << std::endl;
    std::cout << "      RC4 Encryption System      " << std::endl;
    std::cout << "=================================" << std::endl;

    int keyLength;
    std::cout << "\n[Key Setup]" << std::endl;
    std::cout << "Enter key length: ";
    std::cin >> keyLength;

    std::vector<int> key(keyLength);
    std::cout << "Enter " << keyLength << " key bytes (0-255 each): " << std::endl;
    for (int i = 0; i < keyLength; i++)
    {
        std::cin >> key[i];

        if (key[i] < 0 || key[i] > 255)
        {
            std::cout << " Error: Key bytes must be between 0 and 255. Exiting..." << std::endl;
            return 1;
        }
    }

    RC4Cipher rc4(key);

    int messageLength;
    std::cout << "\n[Message Input]" << std::endl;
    std::cout << "Enter message length: ";
    std::cin >> messageLength;

    std::vector<int> plaintext(messageLength);
    std::cout << "Enter " << messageLength << " message bytes (0-255 each): " << std::endl;
    for (int i = 0; i < messageLength; i++)
    {
        std::cin >> plaintext[i];

        if (plaintext[i] < 0 || plaintext[i] > 255)
        {
            std::cout << " Error: Message bytes must be between 0 and 255. Exiting..." << std::endl;
            return 1;
        }
    }

    std::cout << "\n[Original Message]" << std::endl;
    RC4Cipher::displayBytes(plaintext, "Original Bytes:");

    std::cout << "\n[Encryption] " << std::endl;
    std::vector<int> ciphertext = rc4.process(plaintext);
    RC4Cipher::displayBytes(ciphertext, "Encrypted Bytes:");

    std::cout << "\n[Decryption] " << std::endl;
    std::vector<int> decrypted = rc4.process(ciphertext);
    RC4Cipher::displayBytes(decrypted, "Decrypted Bytes:");

    bool decryptionSuccessful = true;
    for (size_t i = 0; i < plaintext.size(); i++)
    {
        if (plaintext[i] != decrypted[i])
        {
            decryptionSuccessful = false;
            break;
        }
    }

    std::cout << "\n[Verification] " << (decryptionSuccessful ? " Successful!" : " Failed!") << std::endl;

    return 0;
}
