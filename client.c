

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#define LIBSSH_STATIC 1
#include <libssh/libssh.h>
#include <pthread.h>

//gcc client.c -I/usr/include/libssh -lssh -lpthread

int ID = 0; //Unique id for thread
int IDorder[10];
char MainCommand[64];

int verify_knownhost(ssh_session session)
{
    enum ssh_known_hosts_e state;
    unsigned char *hash = NULL;
    ssh_key srv_pubkey = NULL;
    size_t hlen;
    char buf[10];
    char *hexa;
    char *p;
    int cmp;
    int rc;
    rc = ssh_get_server_publickey(session, &srv_pubkey);
    if (rc < 0)
    {
        return -1;
    }
    rc = ssh_get_publickey_hash(srv_pubkey,
                                SSH_PUBLICKEY_HASH_SHA1,
                                &hash,
                                &hlen);
    ssh_key_free(srv_pubkey);
    if (rc < 0)
    {
        return -1;
    }
    state = ssh_session_is_known_server(session);
    switch (state)
    {
    case SSH_KNOWN_HOSTS_OK:
        /* OK */
        break;
    case SSH_KNOWN_HOSTS_CHANGED:
        //fprintf(stderr, "Host key for server changed: it is now:\n");
        //ssh_print_hexa("Public key hash", hash, hlen);
        //fprintf(stderr, "For security reasons, connection will be stopped\n");
        //virtual machines change host keys. ^ causes bugs
        rc = ssh_session_update_known_hosts(session);
        if (rc < 0)
        {
            fprintf(stderr, "Error %s\n", strerror(errno));
            return -1;
        }
        break;

        //return -1;
        break;
    case SSH_KNOWN_HOSTS_OTHER:
        fprintf(stderr, "The host key for this server was not found but an other"
                        "type of key exists.\n");
        fprintf(stderr, "An attacker might change the default server key to"
                        "confuse your client into thinking the key does not exist\n");
        ssh_clean_pubkey_hash(&hash);
        return -1;
    case SSH_KNOWN_HOSTS_NOT_FOUND:
        fprintf(stderr, "Could not find known host file.\n");
        fprintf(stderr, "If you accept the host key here, the file will be"
                        "automatically created.\n");
        /* FALL THROUGH to SSH_SERVER_NOT_KNOWN behavior */
    case SSH_KNOWN_HOSTS_UNKNOWN:
        hexa = ssh_get_hexa(hash, hlen);
        fprintf(stderr, "The server is unknown. Do you trust the host key?\n");
        fprintf(stderr, "Public key hash: %s\n", hexa);
        ssh_string_free_char(hexa);
        ssh_clean_pubkey_hash(&hash);
        p = fgets(buf, sizeof(buf), stdin);
        if (p == NULL)
        {
            return -1;
        }
        cmp = strncasecmp(buf, "yes", 3);
        if (cmp != 0)
        {
            return -1;
        }
        rc = ssh_session_update_known_hosts(session);
        if (rc < 0)
        {
            fprintf(stderr, "Error %s\n", strerror(errno));
            return -1;
        }
        break;
    case SSH_KNOWN_HOSTS_ERROR:
        fprintf(stderr, "Error %s", ssh_get_error(session));
        ssh_clean_pubkey_hash(&hash);
        return -1;
    }
    ssh_clean_pubkey_hash(&hash);
    return 0;
}

int execute_command(ssh_session session)
{
    ssh_channel channel;
    int rc;
    char buffer[256];
    int nbytes;

    channel = ssh_channel_new(session);
    if (channel == NULL)
        return SSH_ERROR;

    rc = ssh_channel_open_session(channel);
    if (rc != SSH_OK)
    {
        ssh_channel_free(channel);
        return rc;
    }

    rc = ssh_channel_request_exec(channel, MainCommand);
    if (rc != SSH_OK)
    {
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return rc;
    }

    nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
    while (nbytes > 0)
    {
        if (write(1, buffer, nbytes) != (unsigned int)nbytes)
        {
            ssh_channel_close(channel);
            ssh_channel_free(channel);
            return SSH_ERROR;
        }
        nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
    }

    if (nbytes < 0)
    {
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return SSH_ERROR;
    }

    ssh_channel_send_eof(channel);
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    printf("\n");

    return SSH_OK;
}

int input_check(char *buffer) //Self explanatory
{
    int i = 0, k = 1;
    //printf("primit%s",buffer);
    char command[35];
    command[0] = NULL;
    char *buffer2 = (char *)malloc(sizeof(char) * (strlen(buffer)));
    strcpy(buffer2, buffer);
    while (1)
    {
        if ((buffer[i] >= '0' && buffer[i] <= '9') || buffer[i] == NULL)
        {
            break;
        }
        else
        {
            {
                if (buffer[i] >= 'a' && buffer[i] <= 'z')
                    command[i] = buffer[i];
            }
            i++;
        }
    }
    if (command[0] == NULL)
    {
        printf("invalid\n");
        return -1;
    }
    if(strstr(command,"disconnect"))
    {
        k=2;
    }
    strcpy(MainCommand, command);
    // printf("command=%s\n",command);
    fflush(stdout);
    for (int j = 0; j <= 9; j++)
        IDorder[j] = 0;
    if (buffer[i] != NULL)
    {
        while (buffer[i] != NULL)
        {
            IDorder[buffer[i] - '0'] = k;
            if (strchr(" ,", buffer[i + 1] != NULL))
                break;
            i = i + 2;
        }
    }
    else
    {
        for (int j = 0; j <= 9; j++)
            IDorder[j] = k;
    }

    printf("target=");
    for (int j = 0; j < 10; j++)
        if (IDorder[j] != 0 )   
            printf("%d,", j);
            printf("\n\n");
    fflush(stdout);
    return 0;
}

void connection(char *IP) //Establishes the connection to the host(s)
{
    char *IPadd = (char *)malloc(sizeof(char) * strlen(IP));
    strcpy(IPadd, IP);

    ssh_session my_ssh_session;
    int rc;
    int idlocal;

    char *password;
    // Open session and set options
    my_ssh_session = ssh_new();
    if (my_ssh_session == NULL)
        exit(-1);
    printf("Connecting->%s\n", IPadd);
    ssh_options_set(my_ssh_session, SSH_OPTIONS_HOST, IPadd);
    ssh_options_set(my_ssh_session, SSH_OPTIONS_USER, "root");
    // Connect to server
    rc = ssh_connect(my_ssh_session);
    if (rc != SSH_OK)
    {
        fprintf(stderr, "Error connecting to %s: %s\n",
                IPadd, ssh_get_error(my_ssh_session));
        ssh_free(my_ssh_session);
        //exit(-1);
        return -1;
    }
    // Verify the server's identity
    if (verify_knownhost(my_ssh_session) < 0)
    {
        ssh_disconnect(my_ssh_session);
        ssh_free(my_ssh_session);
        exit(-1);
    }
    // Authenticate ourselves
    password = "toor";
    rc = ssh_userauth_password(my_ssh_session, NULL, password);
    if (rc != SSH_AUTH_SUCCESS)
    {
        fprintf(stderr, "Error authenticating with password: %s\n",
                ssh_get_error(my_ssh_session));
        ssh_disconnect(my_ssh_session);
        ssh_free(my_ssh_session);
        exit(-1);
    }
    else
    {

        printf("Auth Succesful");

        idlocal = ++ID;
        printf("->>%s ID=%d \n", IPadd, idlocal);
    }
    fflush(stdout);
    while (idlocal)
    {
        if (IDorder[idlocal] == 1)
        {
            sleep(1);
            execute_command(my_ssh_session);
            IDorder[idlocal] = 0;
        }
        if(IDorder[idlocal]== 2)
        {
            ssh_disconnect(my_ssh_session);
        ssh_free(my_ssh_session);
        printf("Disconnected from %s \n",IPadd);
        break;
        
        }
    }
    // execute_command(my_ssh_session);
}

int main(int argc, const char **argv)
{
    char buffer[512];
    char * point;
    pthread_t th[100]; //Identificatorii thread-urilor care se vor crea
    int i = 0;
    FILE *file;
    char IP[15];
    file = fopen("IPs.txt", "r");

    while (fgets(IP, 50, file) != NULL)
    {

        IP[strlen(IP) - 1] = NULL;
        //printf("IP->%s\n",IP);
        if (IP != NULL)
            if (strlen(IP) > 10)
            {
                pthread_create(&th[i++], NULL, &connection, IP);
            }
        sleep(1);
    }
    //printf("\nInput: ");

    while (fgets(buffer, 256, stdin), !feof(stdin))
    {

        if (strstr(buffer, "quit"))
            break;
        if(strstr(buffer,"try"))
            {
                int k=0;
                point=strchr(buffer,'1');
                point[strlen(point)-1]=NULL;
                pthread_create(&th[i++], NULL, &connection, point);
                sleep(1);
            }
            else
            {
                fflush(stdout);
        input_check(buffer);
            }
            
        
        
    }

    return 0;
}
