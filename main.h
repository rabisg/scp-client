#ifndef _SCP_H
#define _SCP_H

#include <libssh/libssh.h>
#include "authentication.c"
#include "knownhosts.c"
#include "connect_ssh.c"
#include "myscp.h"

int preserve_mod_time;
int recursive;
int verbosity;

int authenticate(ssh_session session);
int authenticate_kbdint(ssh_session session, const char *password);
int verify_knownhost(ssh_session session);
int request_exec(char *host, char *user, char *port, char *command);
ssh_session connect_ssh(const char *hostname, const char *user, char *, int verbosity);


enum ssh_scp_states {
  SSH_SCP_NEW,            //Data structure just created
  SSH_SCP_WRITE_INITED,   //Gave our intention to write
  SSH_SCP_WRITE_WRITING,  //File was opened and currently writing
  SSH_SCP_READ_INITED,    //Gave our intention to read
  SSH_SCP_READ_REQUESTED, //We got a read request
  SSH_SCP_READ_READING,   //File is opened and reading
  SSH_SCP_ERROR,          //Something bad happened
  SSH_SCP_TERMINATED       //Transfer finished
};

struct ssh_scp_struct {
  ssh_session session;
  int mode;
  int recursive;
  ssh_channel channel;
  char *location;
  enum ssh_scp_states state;
  uint64_t filelen;
  uint64_t processed;
  enum ssh_scp_request_types request_type;
  char *request_name;
  char *warning;
  int request_mode;
};


#endif
