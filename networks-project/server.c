#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <sys/types.h>
#include <signal.h>
#include <stdint.h>

#define MAX_CLIENTS 128
#define BUFFER_SZ 2048

static _Atomic unsigned int cli_count = 0;
static int uid = 10;

// client structure
typedef struct
{
    struct sockaddr_in address; // socket
    int sockfd; // socket file descriptor
    int uid; // user id
    char name[32]; // username
    char calias[32]; // chatroom id
    char public_key_str[32]; // public key of this user (string)
    int public_key; // same public key but int
} client_t;


client_t *clients[MAX_CLIENTS]; // current clients connected

pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;


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
 * is used to represent ip address in readable form
 * @param addr
 */
void print_client_addr (struct sockaddr_in addr)
{
    printf("%d.%d.%d.%d",
           addr.sin_addr.s_addr & 0xff,
           (addr.sin_addr.s_addr & 0xff00) >> 8,
           (addr.sin_addr.s_addr & 0xff0000) >> 16,
           (addr.sin_addr.s_addr & 0xff000000) >> 24);
}


/***
 * adds new client to the current clients
 * deals with race condition by applying mutex
 * @param cl: client to be added
 */
void queue_add (client_t *cl)
{
    pthread_mutex_lock(&clients_mutex);

    for (int i = 0; i < MAX_CLIENTS; ++i)
    {
        if (!clients[i])
        {
            clients[i] = cl;
            break;
        }
    }

    pthread_mutex_unlock(&clients_mutex);
}


/***
 * removes client with uid from the current clients
 * deals with race condition by applying mutex
 * @param uid: uid of the client to be removed
 */
void queue_remove (int uid)
{
    pthread_mutex_lock(&clients_mutex);

    for (int i = 0; i < MAX_CLIENTS; ++i)
    {
        if (clients[i])
        {
            if (clients[i]->uid == uid)
            {
                clients[i] = NULL;
                break;
            }
        }
    }

    pthread_mutex_unlock(&clients_mutex);
}


/***
 * sends message to all the clients in the same room as the
 * client that requests the send
 * excludes the sender from the receiving party
 * @param msg : msg to be broadcasted
 * @param uid_from : uid of the sender
 * @param calias_from : chatroom alias of the sender
 * @param public_key_from : public key used (indirectly) to decrypt the msg
 */
void broadcast_msg (int *msg, int uid_from, char *calias_from, char *public_key_from)
{
    pthread_mutex_lock(&clients_mutex);

    for (int i = 0; i < MAX_CLIENTS; i++) // iterate through all clients
    {
        if (clients[i] && // client valid
            clients[i]->uid != uid_from && // sender cannot receive their msg back
            strcmp(clients[i]->calias, calias_from) == 0) // chatroom aliases of sender and receiver coincide
        {
            // send public key
            if (write(clients[i]->sockfd, public_key_from, 32) < 0)
            {
                perror("ERROR: write to descriptor failed");
                break;
            }
            else
            {
                printf("send to %d with pk: %s with length %lu\n", clients[i]->uid, public_key_from,
                       strlen(public_key_from));
            }
            // send message
            if (write(clients[i]->sockfd, msg, BUFFER_SZ * sizeof(int)) < 0)
            {
                perror("ERROR: write to descriptor failed");
                break;
            }
            else
            {
                // log (cannot decipher from server-side, though)
                for (int j = 0; msg[j] != 0; j++)
                {
                    printf("%d ", msg[j]);
                }
                printf("\n");
            }
        }
    }

    pthread_mutex_unlock(&clients_mutex);
}

/* Handles all communication with the client */
/***
 * handles client on connection
 * checks validity of meta
 * then copies data for the user into clients[] to use later
 * then loops and processes information that client sends to server,
 * calling broadcast_msg function and other
 * @param arg : client connected
 * @return NULL
 */
void *handle_client (void *arg)
{
    char buff_out[BUFFER_SZ];
    char name[32];
    char calias[32];
    char public_key_str[32];
    int leave_flag = 0;

    cli_count++;
    client_t *cli = (client_t *) arg;


    // name handling
    if (recv(cli->sockfd, name, 32, 0) <= 0 ||
        strlen(name) < 2 ||
        strlen(name) >= 32 - 1)
    {
        printf("Didn't enter the name.\n"); // name not correct
        leave_flag = 1;
    }
    else
    {
        strcpy(cli->name, name); // name correct
        if (recv(cli->sockfd, calias, 32, 0) > 0)
        {
            strcpy(cli->calias, calias); // alias correct
            recv(cli->sockfd, public_key_str, 32, 0); // stringified public key
            int public_key = atoi(public_key_str); // to int
            printf("public a %d\n", public_key); // log
            cli->public_key = public_key; // store in the structure int
            strcpy(cli->public_key_str, public_key_str); // store in the structure string
        }
        else
        {
            printf("Didn't enter the chat room alias.\n"); // name not correct
            leave_flag = 1;
        }
    }

    bzero(buff_out, BUFFER_SZ);

    while (1)
    {
        if (leave_flag)
        {
            break;
        }

        int msg_encrypted[BUFFER_SZ]; // message from client
        bzero(msg_encrypted, BUFFER_SZ);
        int rc = recv(cli->sockfd, msg_encrypted, sizeof(msg_encrypted), 0);  // receive msg from client
        if (rc > 0) // on receive
        {
            printf("encrypted msg:\n"); // logging
            int i = 0;
            while (msg_encrypted[i] != 0)
            {
                printf("%d ", msg_encrypted[i++]);
            }
            printf("\n"); // logging end
            // forward msg received to other clients in the same chatroom as the sender client
            broadcast_msg(msg_encrypted,
                          cli->uid,
                          cli->calias,
                          cli->public_key_str
            );
        }
        else if (rc == 0 || strcmp(buff_out, "exit") == 0) // on exit
        {
            sprintf(buff_out, "%s has left\n", cli->name); // log
            printf("%s", buff_out); // log
            leave_flag = 1; // close thread // user leave
        }
        else
        {
            printf("ERROR: -1\n");
            leave_flag = 1; // user leave
        }

        bzero(buff_out, BUFFER_SZ); // avoid mem leak
        bzero(msg_encrypted, BUFFER_SZ);
    }

    /* delete client from queue and yield thread */
    close(cli->sockfd); // close connection with client
    queue_remove(cli->uid); // delete client
    free(cli); // free memory space
    cli_count--;
    pthread_detach(pthread_self()); // yield

    return NULL;
}

int main (int argc, char **argv)
{
    char *ip = "127.0.0.1"; // server ip
    int port = 9090; // server port
    int option = 1;
    int listenfd = 0, connfd = 0;
    struct sockaddr_in serv_addr;
    struct sockaddr_in cli_addr;
    pthread_t tid;

    /* Socket settings */
    listenfd = socket(AF_INET, SOCK_STREAM, 0); // ipv4, tcp, ip
    serv_addr.sin_family = AF_INET; // ipv4
    serv_addr.sin_addr.s_addr = inet_addr(ip); // ip addr
    serv_addr.sin_port = htons(port); // port

    signal(SIGPIPE, SIG_IGN); // ignore pipe signals

    if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, (char *) &option, sizeof(option)) < 0)
    {
        perror("ERROR: setsockopt failed");
        return EXIT_FAILURE;
    }

    // bind socket
    if (bind(listenfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
    {
        perror("ERROR: Socket binding failed");
        return EXIT_FAILURE;
    }

    // listen for connections, pending queue 10
    if (listen(listenfd, 10) < 0)
    {
        perror("ERROR: Socket listening failed");
        return EXIT_FAILURE;
    }

    printf("=== WELCOME TO THE CHATROOM ===\n");

    // server started listening for connections
    while (1)
    {
        socklen_t clilen = sizeof(cli_addr);
        connfd = accept(listenfd, (struct sockaddr *) &cli_addr, &clilen); // accept connection

        /* Check if max clients is reached */
        if ((cli_count + 1) == MAX_CLIENTS) // check if we can accept the client
        {
            printf("Max clients reached. Rejected: ");
            print_client_addr(cli_addr);
            printf(":%d\n", cli_addr.sin_port);
            close(connfd); // close connection if we can't
            continue;
        }

        // client settings
        client_t *cli = (client_t *) malloc(sizeof(client_t)); // memory alloc for client
        cli->address = cli_addr; // store info about client in the structure
        cli->sockfd = connfd;
        cli->uid = uid++;

        // add client to the queue and fork thread
        queue_add(cli);
        pthread_create(&tid, NULL, &handle_client, (void *) cli);

        sleep(1); // to reduce CPU strain
    }
}
