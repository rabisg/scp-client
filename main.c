#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
 
#include <sys/types.h>
#include <sys/stat.h>

#include <ftw.h>
#define TREE_DEPTH 10 //Beyond this ftw would become slower. Refer to ftw man page for more details

#include "main.h"
#include "break.c"

int scp_transfer_file(char *src, char *dst);
int scp_push_directory(char *src, char *dst, int recursive);
int scp_fetch_files(char *dst);
int request_exec(char *host, char *user, char *port, char *command);

ssh_session session;
ssh_scp scp;
char cur_path[256];

int st_mode_to_mode (int mode)
{
    int tmp, tmp1, tmp2;
    tmp = tmp1 = tmp2 = 0;
    if ( mode & S_IRUSR ) tmp += 4;    /* 3 bits for user  */
    if ( mode & S_IWUSR ) tmp += 2;
    if ( mode & S_IXUSR ) tmp += 1;
    if ( mode & S_IRGRP ) tmp1 += 4;    /* 3 bits for group */
    if ( mode & S_IWGRP ) tmp1 += 2;
    if ( mode & S_IXGRP ) tmp1 += 1;
    if ( mode & S_IROTH ) tmp2 += 4;    /* 3 bits for other */
    if ( mode & S_IWOTH ) tmp2 += 2;
    if ( mode & S_IXOTH ) tmp2 += 1;
    return tmp*100 + tmp1*10 + tmp2;
}
char *greatest_substr(const char *src, char *dst, int c)
{   
    char *a = strdup(src);
    char *ret = rindex(a, c);
    while (ret != NULL && a != ret)
    {
        *dst = *a;
        dst = dst+1;
        a = a+1;    
    }
    *dst = '\0';
    return ret;
}

char *rtrim(char *buffer, char *stripchars)
{
        int i = 0;
        /* Right Side */
        char *end = buffer + strlen(buffer) - 1;
right:
        for (i = 0; i < strlen(stripchars); i++) {
                if (*end == stripchars[i]) {
                        *end = '\0';
                        --end;
                        goto right;
                }
        }
        return buffer;
}


static int ftw_callback(const char *path, const struct stat *sb, int typeflag)
{
    if(strstr(path, cur_path) == NULL)        //indicates one level-up(like cd ..)
    {
        char p[256];
        greatest_substr(path, p, '/');
        strcpy(cur_path, p);
        ssh_scp_leave_directory(scp);
    }
    switch (typeflag)
    {
        case FTW_F:
            printf("Transferring file: %s\n", path);
            scp_transfer_file(strdup (path), "");
            break;
    
        case FTW_D:    //indicates one level down
            printf("Entering Directory: %s\n", path);
            scp_push_directory(strdup (path), "", 0);
            strcpy(cur_path, path);
            break;
    
        case FTW_DNR:
            printf("Inaccessible Dir %s: No action taken\n", path);
            break;

        default:
            break;
    }
    return 0;
}

int
main (int argc, char **argv)
{
    session=ssh_new();
    if (session == NULL)
        return 1;

    opterr = 0;
    preserve_mod_time = recursive = verbosity = 0;

    int zero = 0; //Because ssh_options_set expects an int *

    int c;
    while ((c = getopt (argc, argv, "12Cc:i:P:prv")) != -1)
    switch (c)
    {
       case '1':
         if (ssh_options_set(session, SSH_OPTIONS_SSH2, &zero) < 0)
            goto terminate;
         break;
       case '2':
         if (ssh_options_set(session, SSH_OPTIONS_SSH1, &zero) < 0)
            goto terminate;
         break;
       case 'C':
         if (ssh_options_set(session, SSH_OPTIONS_COMPRESSION, "yes") < 0)
            goto terminate;
         break;
       case 'c':
         if (ssh_options_set(session, SSH_OPTIONS_CIPHERS_C_S, optarg) < 0
            || ssh_options_set(session, SSH_OPTIONS_CIPHERS_S_C, optarg) < 0)
            goto terminate;
         break;
       case 'i':
         if (ssh_options_set(session, SSH_OPTIONS_IDENTITY, optarg) < 0)
            goto terminate;
         break;
       case 'P':
         if (ssh_options_set(session, SSH_OPTIONS_PORT_STR, optarg) < 0)
            goto terminate;
         break;
       case 'p':
         preserve_mod_time = 1;
         break;
       case 'r':
         recursive = 1;
         break;
       case 'v':
         verbosity = SSH_LOG_PROTOCOL;
         if (ssh_options_set(session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity) < 0)
            goto terminate;
         break;
       case '?':
         if (optopt == 'c' || optopt == 'P')
           fprintf (stderr, "Option -%c requires an argument.\n", optopt);
         else if (isprint (optopt))
           fprintf (stderr, "Unknown option `-%c'.\n", optopt);
         else
           fprintf (stderr, "Unknown option character `\\x%x'.\n", optopt);
       //Fall-through
       default:
         goto terminate;
    }

    /*Set up source and destination*/
    char *host, *user, *src, *dst;
    int mode;
    char *user1, *host1, *file1;
    char *user2, *host2, *file2;
    if ( argc < optind + 2  )
    {
        //usage();
        goto terminate;
    }
    splice(argv[optind], &user1, &host1, &file1);
    splice(argv[optind + 1], &user2, &host2, &file2);
    if ( strcmp(host1, "localhost") == 0 || strcmp(host1, "127.0.0.1") == 0) host1 = "";
    if ( strcmp(host2, "localhost") == 0 || strcmp(host2, "127.0.0.1") == 0) host2 = "";
    
    if ( strlen(host1) && strlen(host2))
    {
        char command[256];
        sprintf (command, "scp %s %s", file1, argv[optind+1]);
        printf("Executing %s on remote end: %s\n", command, host1);
        if ( !request_exec(host1, user1, NULL, command))
            return 0;
        return 1;
    }
    else
        if (!strlen(host1))
        {
            host = (strlen(host2) != 0) ? strdup (host2) : "localhost";
            user = strdup (user2);
            mode = SSH_SCP_WRITE;
        }
        else
        {
            host = strdup (host1);
            user = strdup (user1);
            mode = SSH_SCP_READ;
        }
        src = strdup(file1);
        dst = strdup(file2);

    if (recursive == 1)
        mode = mode | SSH_SCP_RECURSIVE;
    if (ssh_options_set(session, SSH_OPTIONS_HOST, host) < 0)
        goto terminate;

    if (strlen(user))
        if (ssh_options_set (session, SSH_OPTIONS_USER, user) < 0)
            goto terminate;

    if(ssh_connect(session)){
        fprintf(stderr,"Connection failed : %s\n",ssh_get_error(session));
        goto disconnect;
    }
    if (verify_knownhost(session)<0)
        goto disconnect;

    int auth = authenticate(session);
    if(auth != SSH_AUTH_SUCCESS){
        if(auth == SSH_AUTH_DENIED)
            fprintf(stderr,"Authentication failed\n");
        else
            fprintf(stderr,"Error while authenticating : %s\n",ssh_get_error(session));
        goto disconnect;
    }
    if ((mode & ~SSH_SCP_RECURSIVE) == SSH_SCP_READ)
    {
        char *p = calloc (0, sizeof file2);
        char *r;
        if ((r = greatest_substr(file2, p, '/')) != NULL)
        {
            if (chdir(p) != 0)
            {
                fprintf(stderr, "Invalid Path %s\n", file2);
                goto terminate;
            }
            strcpy(dst, r+1);
        }
        free(p);

        scp = ssh_scp_new (session, mode, src);
        if (scp == NULL)
            goto scp_free;
        if ( ssh_scp_init (scp) != SSH_OK)
            goto scp_free;
        scp_fetch_files(dst);
    }
    //int rc;
    else if( (mode & ~SSH_SCP_RECURSIVE) == SSH_SCP_WRITE)
    {
        /* Break dst into path and file name. Because we won't need
        the full dst again, set dst to be the filename and open
        scp_session with the path */
        char *p = calloc (0, sizeof file2);
        char *r = strlen(file2)>0 ? (greatest_substr(file2, p, '/') != NULL ? rindex(file2, '/')+1: file2) : "";
        if (strlen(p) > 0)
            scp = ssh_scp_new (session, mode | SSH_SCP_RECURSIVE, p);
        else
            scp = ssh_scp_new (session, mode | SSH_SCP_RECURSIVE, ".");

        if (scp == NULL)
            goto scp_free;
        if ( ssh_scp_init (scp) != SSH_OK)
            goto scp_free;
        
        struct stat s;
        if(stat(src, &s) != 0) {
            fprintf(stderr, "%s does not exists", src);
            goto scp_close;
        }
        if (S_ISREG(s.st_mode))
            scp_transfer_file(src, r);
        else if (S_ISDIR(s.st_mode))
            scp_push_directory(src, r, recursive);
        else
            fprintf(stderr, "%s: File type not recognized", src);
    }
    else
    {
        fprintf(stderr, "Invalid Mode. Aborting!!\n");
    }
    ssh_scp_close(scp);
    ssh_scp_free(scp);
    ssh_disconnect (session);
    ssh_free (session);
    return 0;

scp_close:
    ssh_scp_close(scp);

scp_free:
    ssh_scp_free(scp);

disconnect:
    ssh_disconnect (session);

terminate:
    fprintf(stderr, "Error:: %s\n",ssh_get_error(session));
    ssh_free(session);
    return 1;
}

/* Expects src to be the full path and dst to be the file name only */
int scp_transfer_file(char *src, char *dst)
{
    int rc, mode;
    uint64_t length;
    struct stat s;
    stat(src, &s);
    length = s.st_size;
    mode = 644;//st_mode_to_mode(s.st_mode);
    char buffer[length + 1];
    FILE *fp = fopen(src, "r");
    if (fp == NULL) {
        fprintf(stderr, "Could not read file: %s\n", src);
        return -1;
    }
    size_t newLen = fread(buffer, sizeof(char), length, fp);
    if (newLen == 0)
        fprintf(stderr, "Error reading file: %s\n", src);
     else
        buffer[++newLen] = '\0';
    fclose(fp);

    if (dst != NULL && strlen(dst) == 0)
        dst = rindex(src, '/');
    if (dst == NULL)
        dst = strdup(src);
    else dst = dst+1;

    rc = ssh_scp_push_file(scp, dst, length, mode);
    if (rc != SSH_OK)
    {
        fprintf(stderr, "Can't open remote file: %s\n", ssh_get_error(session));
        return rc;
    }
    rc = ssh_scp_write(scp, buffer, length);
    if (rc != SSH_OK)
    {
        fprintf(stderr, "Can't write to remote file: %s\n", ssh_get_error(session));
        return rc;
    }
    return SSH_OK;
}

/* Expects src to be the full path and dst to be the file name only */
int scp_push_directory(char *src, char *dst, int recursive)
{
    if (recursive == 1)
    {
        strcpy(cur_path, rtrim(src, "/"));
        ftw(src, ftw_callback, TREE_DEPTH);
        return SSH_OK;
    }

    int rc, mode;
    long long length;
    struct stat s;
    stat(src, &s);
    length = s.st_size;
    mode = 755;//st_mode_to_mode(s.st_mode);
    if (!S_ISDIR(s.st_mode)) {
        fprintf(stderr, "Not a directory: %s", src);
        return -1;
    }
    if (!strcmp(src, "."))
        src = getcwd(NULL, 0);
    if (!strlen(dst))
    {

        dst = ssh_basename(src);
    }
    fprintf(stderr, "Pushing directory: %s\n", dst);
    rc = ssh_scp_push_directory(scp, dst, mode);
    if (rc != SSH_OK)
    {
        char msg[128];
        fprintf(stderr, "Can't open remote directory: %s\n", ssh_get_error(session));
        ssh_channel_read(scp->channel,msg,sizeof(msg), 0);
        fprintf(stderr, "%s\n",msg);
        return 1;
    }
    return SSH_OK;
}

int scp_fetch_files(char *dst)
{
    int size, length;
    int mode;
    char *filename;
    int r;
    char *buffer;
    printf("Trying to download files\n");

    do {
        r=ssh_scp_pull_request(scp);
        switch(r){
        case SSH_SCP_REQUEST_NEWFILE:
            length=ssh_scp_request_get_size(scp);
            size = length < 65536 ? size : 65536;
            filename=strdup(ssh_scp_request_get_filename(scp));
            mode=ssh_scp_request_get_permissions(scp);
            printf("downloading file %s, size %d, perms 0%o\n",filename,length,mode);
            FILE *fd;
            if(strlen(dst)==0)
                fd = fopen(filename, "w");
            else 
                fd = fopen(dst, "w");
            free(filename);

            ssh_scp_accept_request(scp);
            buffer = malloc(size);
            do
            {
                r=ssh_scp_read(scp,buffer,size);
                if(r == SSH_ERROR){
                    fprintf(stderr,"Error reading scp: %s\n",ssh_get_error(session));
                    return -1;
                }
                fprintf(fd, "%s", buffer);
            } while (scp->state == SSH_SCP_READ_READING);
            free(buffer);
            fclose(fd);
            if(strlen(dst)==0)
                chmod(filename, mode);
            else {
                chmod(dst, mode);
                strcpy(dst, "");
            }
            break;

        case SSH_ERROR:
            fprintf(stderr,"Error: %s\n",ssh_get_error(session));
            return -1;

        case SSH_SCP_REQUEST_WARNING:
            fprintf(stderr,"Warning: %s\n",ssh_scp_request_get_warning(scp));
            break;

        case SSH_SCP_REQUEST_NEWDIR:
            filename=strdup(ssh_scp_request_get_filename(scp));
            mode=ssh_scp_request_get_permissions(scp);
            printf("downloading directory %s, perms 0%o\n",filename,mode);
            if (!strlen(dst)) {
                mkdir(filename, mode);
                chdir(dst);
                chdir(filename);
            }
            else {
                mkdir(dst, mode);
                chmod(dst, mode);
                chdir(dst);
                strcpy(dst, "");
            }
            free(filename);
            ssh_scp_accept_request(scp);
            break;

        case SSH_SCP_REQUEST_ENDDIR:
            chdir("..");
            printf("End of directory\n");
            break;

        case SSH_SCP_REQUEST_EOF:
            printf("End of requests\n");
            return 0;

        default:
            printf("Invalid Request Response %d\n", r);
            break;
    }
  } while (1);
  return 0;
}

int request_exec(char *host, char *user, char *port, char *command) {
    ssh_channel channel;
    char buffer[256];
    int nbytes;
    int rc;

    session = connect_ssh(host, user, port, 0);
    if (session == NULL) {
        ssh_finalize();
        return 1;
    }

    channel = ssh_channel_new(session);;
    if (channel == NULL) {
        ssh_disconnect(session);
        ssh_free(session);
        ssh_finalize();
        return 1;
    }

    rc = ssh_channel_open_session(channel);
    if (rc < 0) {
        goto failed;
    }

    rc = ssh_channel_request_exec(channel, command);
    if (rc < 0) {
        goto failed;
    }

    nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
    while (nbytes > 0) {
        if (fwrite(buffer, 1, nbytes, stdout) != (unsigned int) nbytes) {
            goto failed;
        }
        nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
    }

    if (nbytes < 0) {
        goto failed;
    }

    ssh_channel_send_eof(channel);
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    ssh_disconnect(session);
    ssh_free(session);
    ssh_finalize();
    return 0;

failed:
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    ssh_disconnect(session);
    ssh_free(session);
    ssh_finalize();
    return 1;
}
