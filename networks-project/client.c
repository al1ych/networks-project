#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <math.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>

#define LENGTH 2048

const int G = 5; // public
const int P = 23; // public

// Global variables
int SHARED_KEY = 3; // recomputed on each message retrieval // default value is irrelevant
int OUR_PUBLIC_KEY = -1; // computed by formula g^private % p // default value is irrelevant
int OUR_PRIVATE_KEY = 1; // chosen at random // default value is irrelevant
int PUBLIC_KEY_FIRST = 0; // flag

volatile sig_atomic_t exit_flag = 0; // is set to 1 when exit
int sockfd = 0; // socket descriptor
char name[32]; // user name < console
char calias[32]; // chat alias < console

/***
 * processes array arr of chars
 * goes through all the characters in the array and puts
 * terminal symbol in place of endline symbols
 * @param arr
 * @param length
 */
void str_trim_lf (char *arr, int length)
{
    int i;
    for (i = 0; i < length; i++)
    { // trim \n
        if (arr[i] == '\n')
        {
            arr[i] = '\0';
            break;
        }
    }
}

/***
 * used to signal upon closing the client
 * sets exit_flag to 1, which signifies
 * the endpoint of the application
 * it catches ctrl+c signal and sends message about the intention to leave the server
 * over to all the other clients in the chatroom through server and broadcasting
 * @param sig
 */
void catch_ctrl_c_and_exit (int sig)
{
    exit_flag = 1;
}

/***
 * fast power raising
 * computes a^b % m
 * O(log(b))
 * @param a base
 * @param b power
 * @param m module
 * @return a^b % m
 */
int bpow (int a, int b, int m)
{
    if (b == 0) // any number to the power of 0 = 1
    {
        return 1;
    }
    int c = bpow(a, b / 2, m);
    if (b % 2 == 0) // if power is even
    {
        return c * c % m; // then we can compute a^(b/2) and multiply them together
    }
    else
    {
        return c * c * a % m; // a^(b/2) * a^(b/2) * a = a^b
    }
}

/***
 * is used to compute public key from private key:
 *  g^private % p, g=G, a=private, p=P
 * or shared key from public and private keys:
 *  public^private % p, g=public, a=private, p=P
 * @return g^a % p
 */
int compute_key (int g, int a, int p)
{
    return bpow(g, a, p);
}

/***
 * wrapper for compatibility: not every compiler has the itoa method,
 * so we implemented custom itoa for compatibility
 * converts int -> str
 * note: implementation borrowed from internet under open license
 * @param val: integer number to be converted into string
 * @param base: base system
 * @return val converted to string
 */
char *myItoa (int val, int base)
{
    static char buf[32] = {0};
    int i = 30;
    for (; val && i; --i, val /= base)
    {
        buf[i] = "0123456789abcdef"[val % base];
    }
    return &buf[i + 1];
}

/***
 * decrypts message using secret key given in the parameters
 *  shared key should be calculated/recalculated prior to calling this function with this shared key
 * @param message_enc: message to be decrypted
 * @param message_enc_len: length of the array message_enc
 * @param secret_key: key to decrypt with
 * @return decrypted message converted to string
 */
char *decrypt_msg (int message_enc[], int message_enc_len, int secret_key)
{
    char *pass_enc_char = malloc(message_enc_len + 1); // reserve memory to be returned
    pass_enc_char[message_enc_len] = '\0';
    for (int i = 0; message_enc[i] != 0; i++)
    {
        pass_enc_char[i] = (char) (message_enc[i] / secret_key); // decrypted value is code of char / key
    }
    return pass_enc_char;
}

/***
 * encrypts message using secret key given in the parameters
 *  shared key should be calculated/recalculated prior to calling this function with this shared key
 * the message is then converted into an array of ints to avoid overflow of char type
 * @param message: string to be encrypted
 * @param message_len: length of the array message
 * @param secret_key: key to encrypt with
 * @return encrypted message converted to int
 */
int *encrypt_msg (char message[], int message_len, int secret_key)
{
    int *pass_enc = malloc(message_len * sizeof(int)); // reserve memory to be returned
    for (int i = 0; i < message_len; i++)
    {
        pass_enc[i] = (int) (message[i]) * secret_key; // encrypted value is code of char * key
    }
    return pass_enc;
}

/***
 * function that is running in the sender thread
 * it gets messages from console when the user enters them
 * and then sends them over to the server to be further processed and broadcasted
 * to other users in the same chatroom
 */
void sender_th ()
{
    char msg[LENGTH]; // message buffer
    char msg_formatted[LENGTH + 32]; // message formatted

    int tick = -1;
    while (1)
    {
        tick++;
        if (tick == 0) // this deals with initial key exchange problem
        {
            strcpy(msg, "hello");
        }
        else
        {
            fgets(msg, LENGTH, stdin);
        }

        str_trim_lf(msg, strlen(msg)); // \n->\0

        if (strcmp(msg, "exit") == 0) // type 'exit' to quit the app
        {
            break;
        }
        else
        {
            sprintf(msg_formatted, "%s: %s", name, msg); // include name in message
            int *msg_encrypted = encrypt_msg(msg_formatted, strlen(msg_formatted), SHARED_KEY); // encrypt msg
            send(sockfd, msg_encrypted, strlen(msg_formatted) * 4, 0); // send msg
        }

        bzero(msg, LENGTH); // avoid mem leak
        bzero(msg_formatted, LENGTH + 32); // avoid mem leak
    }

    catch_ctrl_c_and_exit(2); // mark exit
}

/***
 * function that is running constantly in the receiver thread
 * it receives messages coming from the server and shows the result
 * out on the console for the user to read the messages
 *
 * upon receiving a message, it recomputes the shared key with the one sent in the message
 * the message is then processed and decrypted
 * after that it will show it in the console
 */
void receiver_th ()
{
    int msg[LENGTH] = {}; // msg buffer
    char public_key_str[32] = {}; // stringified public key buffer
    while (1)
    {
        // take public key str that server sends with msg
        size_t receive_public_key = recv(
            sockfd,
            public_key_str,
            32,
            0
        );
        if (receive_public_key > 0) // if received
        {
            int public_key_other = atoi(public_key_str); // convert back to int
            if (public_key_other != 0)
            {
                SHARED_KEY = compute_key(public_key_other, OUR_PRIVATE_KEY, P); // recompute shared key
            }
        }
        else if (receive_public_key == 0) // not received
        {
            break;
        }

        size_t receive_msg = recv(sockfd, msg, LENGTH * sizeof(int), 0); // receive the msg itself (encrypted)

        if (receive_msg > 0) // if received
        {
            char *msg_decrypted = decrypt_msg(msg, LENGTH, SHARED_KEY); // decrypt msg
            if (strlen(msg_decrypted) != 0) // if msg is not empty, we process it
            {
                if (PUBLIC_KEY_FIRST == 0)
                {
                    PUBLIC_KEY_FIRST = 1;
                    char welcome_msg[64];
                    strcat(welcome_msg, name);
                    int *msg_encrypted = encrypt_msg(
                        strcat(welcome_msg, " has joined the room"),
                        64,
                        SHARED_KEY
                    );
                    send(sockfd, msg_encrypted, 64 * 4, 0); // send encrypted invisible welcome msg
                }
                else
                {
                    printf("%s\n", msg_decrypted); // print to the console the received msg (decrypted)
                }
            }
        }
        else if (receive_msg == 0) // if not received
        {
            break;
        }

        memset(msg, 0, sizeof(msg)); // avoid memory leak
        memset(public_key_str, 0, sizeof(public_key_str)); // avoid memory leak
    }
}

int main (int argc, char **argv)
{
    srand(time(NULL)); // randomization seed // to increase randomness

    char *ip = "127.0.0.1"; // server ip
    int port = 9090; // server port

    signal(SIGINT, catch_ctrl_c_and_exit); // catches ctrl+c exit 'event'

    printf("Username: "); // ask user for name
    fgets(name, 32, stdin);
    str_trim_lf(name, strlen(name)); // process name

    printf("Chatroom alias: "); // ask user for chatroom alias
    fgets(calias, 32, stdin);
    str_trim_lf(calias, strlen(calias)); // process calias


    if (strlen(name) > 32 || strlen(name) < 2) // check validity of name
    {
        printf("Name must be less than 30 and more than 2 characters.\n");
        return EXIT_FAILURE;
    }

    struct sockaddr_in server_addr;

    // socket settings
    sockfd = socket(AF_INET, SOCK_STREAM, 0); // ipv4, tcp, ip
    server_addr.sin_family = AF_INET; // ipv4
    server_addr.sin_addr.s_addr = inet_addr(ip); // ip addr
    server_addr.sin_port = htons(port); // port


    // connect to the server
    int err = connect(sockfd, (struct sockaddr *) &server_addr, sizeof(server_addr));
    if (err == -1)
    {
        printf("ERROR: connect\n");
        return EXIT_FAILURE;
    }


    // Diffie-Hellman encryption setup
    OUR_PRIVATE_KEY = rand() % 20; // selected at random between 0 and 19, integer
    OUR_PUBLIC_KEY = compute_key(G, OUR_PRIVATE_KEY, P); // g ^ private % p
    char *public_key_str = myItoa(OUR_PUBLIC_KEY, 10); // convert to string to send to server this way

    // send meta
    send(sockfd, name, 32, 0); // send name
    send(sockfd, calias, 32, 0); // send calias
    send(sockfd, public_key_str, 32, 0); // send public key stringified
//    printf("\nprivate_key: %d\npublic_key_str: %s\n", OUR_PRIVATE_KEY, public_key_str); // debug
//    printf("shared key: %d\n", SHARED_KEY); // debug


    printf("=== CHATROOM ===\n");

    pthread_t sender_thread; // sender thread
    if (pthread_create(&sender_thread, NULL, (void *) sender_th, NULL) != 0)
    {
        printf("ERROR: pthread\n");
        return EXIT_FAILURE;
    }

    pthread_t receiver_thread; // receiver thread
    if (pthread_create(&receiver_thread, NULL, (void *) receiver_th, NULL) != 0)
    {
        printf("ERROR: pthread\n");
        return EXIT_FAILURE;
    }

    while (1) // start a loop
    {
        if (exit_flag) // to be constantly checking for exit_flag on condition ctrl+c
        {
            printf("\nBye\n");
            break;
        }
    }

    close(sockfd); // close connection
}

