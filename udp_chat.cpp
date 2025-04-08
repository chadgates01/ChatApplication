#include <iostream>
#include <string>
#include <thread>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")

#define CHAT_PORT 5000
#define MULTICAST_GROUP "239.0.0.1"

using namespace std;

class ChatClient
{
private:
    string userId;
    string encryptionKey = "secret";
    SOCKET sock;
    sockaddr_in groupAddr;

public:
    ChatClient() : sock(INVALID_SOCKET) {}

    ~ChatClient()
    {
        if (sock != INVALID_SOCKET)
        {
            closesocket(sock);
        }
        WSACleanup();
    }

    void run()
    {
        setupUser();
        if (!initializeNetwork())
            return;

        thread recvThread(&ChatClient::receiveMessages, this);
        sendMessages();
        recvThread.join();
    }

private:
    void setupUser()
    {
        cout << "Welcome to Secure Multicast Chat!" << endl;
        cout << "Enter your username: ";
        getline(cin, userId);
    }

    bool initializeNetwork()
    {
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
        {
            cerr << "WSAStartup failed.\n";
            return false;
        }

        sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock == INVALID_SOCKET)
        {
            cerr << "Socket creation failed.\n";
            WSACleanup();
            return false;
        }

        BOOL reuse = TRUE;
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse, sizeof(reuse));

        sockaddr_in localAddr{};
        localAddr.sin_family = AF_INET;
        localAddr.sin_port = htons(CHAT_PORT);
        localAddr.sin_addr.s_addr = htonl(INADDR_ANY);
        if (bind(sock, (sockaddr *)&localAddr, sizeof(localAddr)) == SOCKET_ERROR)
        {
            cerr << "Bind failed.\n";
            return false;
        }

        ip_mreq mreq{};
        mreq.imr_multiaddr.s_addr = inet_addr(MULTICAST_GROUP);
        mreq.imr_interface.s_addr = htonl(INADDR_ANY);
        if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *)&mreq, sizeof(mreq)) == SOCKET_ERROR)
        {
            cerr << "Failed to join multicast group.\n";
            return false;
        }

        groupAddr.sin_family = AF_INET;
        groupAddr.sin_port = htons(CHAT_PORT);
        groupAddr.sin_addr.s_addr = inet_addr(MULTICAST_GROUP);

        return true;
    }

    void rc4EncryptDecrypt(string &data, const string &key)
    {
        unsigned char S[256];
        for (int i = 0; i < 256; i++)
            S[i] = i;

        int j = 0;
        for (int i = 0; i < 256; i++)
        {
            j = (j + S[i] + key[i % key.size()]) % 256;
            swap(S[i], S[j]);
        }

        int i = 0;
        j = 0;
        for (int k = 0; k < data.size(); k++)
        {
            i = (i + 1) % 256;
            j = (j + S[i]) % 256;
            swap(S[i], S[j]);
            data[k] ^= S[(S[i] + S[j]) % 256];
        }
    }

    void receiveMessages()
    {
        char buffer[1024];
        sockaddr_in senderAddr;
        int senderAddrLen = sizeof(senderAddr);

        while (true)
        {
            int length = recvfrom(sock, buffer, sizeof(buffer) - 1, 0, (sockaddr *)&senderAddr, &senderAddrLen);
            if (length > 0)
            {
                buffer[length] = '\0';
                string encrypted(buffer);
                rc4EncryptDecrypt(encrypted, encryptionKey);

                string senderName = encrypted.substr(0, encrypted.find(":"));
                string messageContent = encrypted.substr(encrypted.find(":") + 1);

                if (senderName != userId &&
                    (messageContent.find("@" + userId) != string::npos || messageContent.find("@ALL") != string::npos))
                {
                    cout << "\n" << senderName << ": " << messageContent << endl;
                    cout << "\nWho do you want to message? \n(1) All  \n(2) Specific User\n> ";
                    cout.flush();
                }
            }
        }
    }

    void sendMessages()
    {
        while (true)
        {
            string choice;
            cout << "\nWho do you want to message? (1) All  (2) Specific User\n> ";
            getline(cin, choice);

            string target, message;
            if (choice == "1")
            {
                target = "ALL";
            }
            else if (choice == "2")
            {
                cout << "Enter recipient's username: ";
                getline(cin, target);
            }
            else
            {
                cout << "Invalid choice.\n";
                continue;
            }

            cout << "Enter your message (type /exit to quit): ";
            getline(cin, message);

            if (message == "/exit")
            {
                cout << "Exiting chat...\n";
                break;
            }

            string formattedMessage = userId + ":@" + target + " " + message;
            rc4EncryptDecrypt(formattedMessage, encryptionKey);

            sendto(sock, formattedMessage.c_str(), formattedMessage.size(), 0, (sockaddr *)&groupAddr, sizeof(groupAddr));
        }
    }
};

int main()
{
    ChatClient client;
    client.run();
    return 0;
}
