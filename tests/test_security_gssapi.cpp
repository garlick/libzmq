/*
    Copyright (c) 2007-2017 Contributors as noted in the AUTHORS file

    This file is part of libzmq, the ZeroMQ core engine in C++.

    libzmq is free software; you can redistribute it and/or modify it under
    the terms of the GNU Lesser General Public License (LGPL) as published
    by the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    As a special exception, the Contributors give you permission to link
    this library with independent modules to produce an executable,
    regardless of the license terms of these independent modules, and to
    copy and distribute the resulting executable under terms of your choice,
    provided that you also meet, for each linked independent module, the
    terms and conditions of the license of that module. An independent
    module is a module which is not derived from or based on this library.
    If you modify this library, you must extend this exception to your
    version of the library.

    libzmq is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
    FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public
    License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "testutil.hpp"
#if defined (ZMQ_HAVE_WINDOWS)
#   include <winsock2.h>
#   include <ws2tcpip.h>
#   include <stdexcept>
#   define close closesocket
#else
#   include <sys/socket.h>
#   include <netinet/in.h>
#   include <arpa/inet.h>
#   include <unistd.h>
#endif

//  This test requires a KRB5 environment with the following
//  test principals (substitute your host.domain and REALM):
//
//    zmqtest1@REALM
//    zmqtest2/host.domain@REALM   (host.domain should be host running test)
//    zmqtest3/client@REALM
//    zmqtest4/client@REALM
//
//  Export keys for these principals to a single keytab file and set the
//  environment variables KRB5_KTNAME and KRB5_CLIENT_KTNAME to point to it,
//  e.g. FILE:/path/to/your/keytab.
//
//  This test is derived in large part from test_security_curve.cpp


struct gss_name {
    const char *name;
    int type;
};

const struct gss_name names[] = {
    { "zmqtest1",        ZMQ_GSSAPI_NT_USER_NAME },
    { "zmqtest2",        ZMQ_GSSAPI_NT_HOSTBASED },
    { "zmqtest3/client", ZMQ_GSSAPI_NT_KRB5_PRINCIPAL },
    { "zmqtest4/server", ZMQ_GSSAPI_NT_KRB5_PRINCIPAL },
    { NULL, 0 },
};

//  Read one event off the monitor socket; return value and address
//  by reference, if not null, and event number by value. Returns -1
//  in case of error.

static int
get_monitor_event (void *monitor, int *value, char **address)
{
    //  First frame in message contains event number and value
    zmq_msg_t msg;
    zmq_msg_init (&msg);
    if (zmq_msg_recv (&msg, monitor, 0) == -1)
        return -1;              //  Interruped, presumably
    assert (zmq_msg_more (&msg));

    uint8_t *data = (uint8_t *) zmq_msg_data (&msg);
    uint16_t event = *(uint16_t *) (data);
    if (value)
        *value = *(uint32_t *) (data + 2);

    //  Second frame in message contains event address
    zmq_msg_init (&msg);
    if (zmq_msg_recv (&msg, monitor, 0) == -1)
        return -1;              //  Interruped, presumably
    assert (!zmq_msg_more (&msg));

    if (address) {
        uint8_t *data = (uint8_t *) zmq_msg_data (&msg);
        size_t size = zmq_msg_size (&msg);
        *address = (char *) malloc (size + 1);
        memcpy (*address, data, size);
        *address [size] = 0;
    }
    return event;
}

//  --------------------------------------------------------------------------
//  This methods receives and validates ZAP requestes (allowing or denying
//  each client connection).

static void zap_handler (void *handler)
{
    //  Process ZAP requests forever
    while (true) {
        char *version = s_recv (handler);
        if (!version)
            break;          //  Terminating

        char *sequence = s_recv (handler);
        char *domain = s_recv (handler);
        char *address = s_recv (handler);
        char *identity = s_recv (handler);
        char *mechanism = s_recv (handler);
        char *principal = s_recv (handler);

        assert (streq (version, "1.0"));
        assert (streq (mechanism, "GSSAPI"));

        s_sendmore (handler, version);
        s_sendmore (handler, sequence);

        //  Deny zmqtest4/server.
        //  Allow all others.
        if (strncmp (principal, names[3].name, strlen (names[3].name)) != 0) {
            s_sendmore (handler, "200");
            s_sendmore (handler, "OK");
            s_sendmore (handler, "anonymous");
            s_send     (handler, "");
            //fprintf (stderr, "ALLOW %s\n", principal);
        }
        else {
            s_sendmore (handler, "400");
            s_sendmore (handler, "Denied");
            s_sendmore (handler, "");
            s_send     (handler, "");
            //fprintf (stderr, "DENY %s\n", principal);
        }
        free (version);
        free (sequence);
        free (domain);
        free (address);
        free (identity);
        free (mechanism);
        free (principal);
    }
    zmq_close (handler);
}

void test_valid_creds (void *ctx, void *server, void *server_mon,
                       const struct gss_name *cli_name,
                       const struct gss_name *srv_name)
{
    void *client = zmq_socket (ctx, ZMQ_DEALER);
    assert (client);
    int rc = zmq_setsockopt (client, ZMQ_GSSAPI_SERVICE_PRINCIPAL,
                             srv_name->name, strlen (srv_name->name) + 1);
    assert (rc == 0);
    rc = zmq_setsockopt (client, ZMQ_GSSAPI_SERVICE_PRINCIPAL_NAMETYPE,
                         &srv_name->type, sizeof (int));
    assert (rc == 0);
    rc = zmq_setsockopt (client, ZMQ_GSSAPI_PRINCIPAL,
                         cli_name->name, strlen (cli_name->name) + 1);
    assert (rc == 0);
    rc = zmq_setsockopt (client, ZMQ_GSSAPI_PRINCIPAL_NAMETYPE,
                         &cli_name->type, sizeof (int));
    assert (rc == 0);
    rc = zmq_connect (client, "tcp://localhost:9998");
    assert (rc == 0);

    bounce (server, client);
    rc = zmq_close (client);
    assert (rc == 0);

    int event = get_monitor_event (server_mon, NULL, NULL);
    assert (event == ZMQ_EVENT_HANDSHAKE_SUCCEED);
}

//  Check security with valid but unauthorized credentials
void test_unauth_creds (void *ctx, void *server, void *server_mon,
                        const struct gss_name *cli_name,
                        const struct gss_name *srv_name)
{
    void *client = zmq_socket (ctx, ZMQ_DEALER);
    assert (client);
    int rc = zmq_setsockopt (client, ZMQ_GSSAPI_SERVICE_PRINCIPAL,
                             srv_name->name, strlen (srv_name->name) + 1);
    assert (rc == 0);
    rc = zmq_setsockopt (client, ZMQ_GSSAPI_SERVICE_PRINCIPAL_NAMETYPE,
                         &srv_name->type, sizeof (int));
    assert (rc == 0);
    rc = zmq_setsockopt (client, ZMQ_GSSAPI_PRINCIPAL,
                         cli_name->name, strlen (cli_name->name) + 1);
    assert (rc == 0);
    rc = zmq_setsockopt (client, ZMQ_GSSAPI_PRINCIPAL_NAMETYPE,
                         &cli_name->type, sizeof (int));
    assert (rc == 0);

    rc = zmq_connect (client, "tcp://localhost:9998");
    assert (rc == 0);

    expect_bounce_fail (server, client);
    close_zero_linger (client);

    int event = get_monitor_event (server_mon, NULL, NULL);
    assert (event == ZMQ_EVENT_HANDSHAKE_FAILED);
}

//  Check GSSAPI security with NULL client credentials
//  This must be caught by the gssapi_server class, not passed to ZAP
void test_null_creds (void *ctx, void *server, void *server_mon)
{
    void *client = zmq_socket (ctx, ZMQ_DEALER);
    assert (client);
    int rc = zmq_connect (client, "tcp://localhost:9998");
    assert (rc == 0);
    expect_bounce_fail (server, client);
    close_zero_linger (client);

    int event = get_monitor_event (server_mon, NULL, NULL);
    assert (event == ZMQ_EVENT_HANDSHAKE_FAILED);
}

//  Check GSSAPI security with PLAIN client credentials
//  This must be caught by the curve_server class, not passed to ZAP
void test_plain_creds (void *ctx, void *server, void *server_mon)
{
    void *client = zmq_socket (ctx, ZMQ_DEALER);
    assert (client);
    int rc = zmq_setsockopt (client, ZMQ_PLAIN_USERNAME, "admin", 5);
    assert (rc == 0);
    rc = zmq_setsockopt (client, ZMQ_PLAIN_PASSWORD, "password", 8);
    assert (rc == 0);
    expect_bounce_fail (server, client);
    close_zero_linger (client);
}

// Unauthenticated messages from a vanilla socket shouldn't be received
void test_vanilla_socket (void *ctx, void *server, void *server_mon)
{
    struct sockaddr_in ip4addr;
    int s;
    ip4addr.sin_family = AF_INET;
    ip4addr.sin_port = htons (9998);
#if defined (ZMQ_HAVE_WINDOWS) && (_WIN32_WINNT < 0x0600)
    ip4addr.sin_addr.s_addr = inet_addr ("127.0.0.1");
#else
    inet_pton(AF_INET, "127.0.0.1", &ip4addr.sin_addr);
#endif

    s = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
    int rc = connect (s, (struct sockaddr*) &ip4addr, sizeof (ip4addr));
    assert (rc > -1);
    // send anonymous ZMTP/1.0 greeting
    send (s, "\x01\x00", 2, 0);
    // send sneaky message that shouldn't be received
    send (s, "\x08\x00sneaky\0", 9, 0);
    int timeout = 250;
    zmq_setsockopt (server, ZMQ_RCVTIMEO, &timeout, sizeof (timeout));
    char *buf = s_recv (server);
    if (buf != NULL) {
        printf ("Received unauthenticated message: %s\n", buf);
        assert (buf == NULL);
    }
    close (s);
}

void setup_server (void *ctx, void **serverp, void **server_monp,
                   const struct gss_name *name)
{
    //  Server socket will accept connections
    void *server = zmq_socket (ctx, ZMQ_DEALER);
    assert (server);
    int as_server = 1;
    int rc;
    rc = zmq_setsockopt (server, ZMQ_GSSAPI_SERVER, &as_server, sizeof (int));
    assert (rc == 0);
    rc = zmq_setsockopt (server, ZMQ_GSSAPI_PRINCIPAL,
                         name->name, strlen (name->name) + 1);
    assert (rc == 0);
    int name_type = name->type;
    rc = zmq_setsockopt (server, ZMQ_GSSAPI_PRINCIPAL_NAMETYPE,
                         &name_type, sizeof (name_type));
    assert (rc == 0);
    rc = zmq_bind (server, "tcp://127.0.0.1:9998");
    assert (rc == 0);

    //  Monitor handshake events on the server
    char endpoint[128];
    snprintf (endpoint, sizeof (endpoint), "inproc://monitor-%s", name->name);
    rc = zmq_socket_monitor (server, endpoint,
            ZMQ_EVENT_HANDSHAKE_SUCCEED | ZMQ_EVENT_HANDSHAKE_FAILED);
    assert (rc == 0);

    //  Create socket for collecting monitor events
    void *server_mon = zmq_socket (ctx, ZMQ_PAIR);
    assert (server_mon);

    //  Connect it to the inproc endpoints so they'll get events
    rc = zmq_connect (server_mon, endpoint);
    assert (rc == 0);

    *serverp = server;
    *server_monp = server_mon;
}

void destroy_server (void *server, void *server_mon)
{
    close_zero_linger (server_mon);
    int rc = zmq_close (server);
    assert (rc == 0);
}

//  The DIR: ccache type seems to avoid problems with client changing
//  its principal name on the fly.  With FILE: or MEMORY, principal from
//  ccache takes precedence over new desired name.
//  FIXME: need to rm -r this directory when the test ends
void setup_ccache (void)
{
    char *tmpdir = getenv ("TMPDIR");
    char buf[1024];
    snprintf (buf, sizeof (buf), "DIR:%s/krb5cc_zmqtest.XXXXXX",
              tmpdir ? tmpdir : "/tmp");
    char *path = mkdtemp (buf + 4);
    assert (path != NULL);
    int rc = setenv ("KRB5CCNAME", buf, 1);
    assert (rc == 0);
}

int main (void)
{
    void *server;
    void *server_mon;

    if (!getenv ("KRB5_KTNAME") || !getenv ("KRB5_CLIENT_KTNAME")) {
        printf ("KRB5 environment unavailable, skipping test\n");
        return 77; // SKIP
    }
    setup_test_environment ();
    setup_ccache ();

    void *ctx = zmq_ctx_new ();
    assert (ctx);

    //  Spawn ZAP handler
    //  We create and bind ZAP socket in main thread to avoid case
    //  where child thread does not start up fast enough.
    void *handler = zmq_socket (ctx, ZMQ_REP);
    assert (handler);
    int rc = zmq_bind (handler, "inproc://zeromq.zap.01");
    assert (rc == 0);
    void *zap_thread = zmq_threadstart (&zap_handler, handler);

    //fprintf (stderr, "Run server=%s\n", names[1].name);
    setup_server (ctx, &server, &server_mon, &names[1]);
    test_valid_creds (ctx, server, server_mon, &names[0], &names[1]);
    test_valid_creds (ctx, server, server_mon, &names[1], &names[1]);
    test_valid_creds (ctx, server, server_mon, &names[2], &names[1]);
    test_unauth_creds (ctx, server, server_mon, &names[3], &names[1]);
    test_null_creds (ctx, server, server_mon);
    test_plain_creds (ctx, server, server_mon);
    test_vanilla_socket (ctx, server, server_mon);
    destroy_server (server, server_mon);

    //fprintf (stderr, "Run server=%s\n", names[0].name);
    setup_server (ctx, &server, &server_mon, &names[0]);
    test_valid_creds (ctx, server, server_mon, &names[0], &names[0]);
    test_valid_creds (ctx, server, server_mon, &names[1], &names[0]);
    test_valid_creds (ctx, server, server_mon, &names[2], &names[0]);
    test_unauth_creds (ctx, server, server_mon, &names[3], &names[0]);
    destroy_server (server, server_mon);

    //fprintf (stderr, "Run server=%s\n", names[3].name);
    setup_server (ctx, &server, &server_mon, &names[3]);
    test_valid_creds (ctx, server, server_mon, &names[0], &names[3]);
    test_valid_creds (ctx, server, server_mon, &names[1], &names[3]);
    test_valid_creds (ctx, server, server_mon, &names[2], &names[3]);
    test_unauth_creds (ctx, server, server_mon, &names[3], &names[3]);
    destroy_server (server, server_mon);

    rc = zmq_ctx_term (ctx);
    assert (rc == 0);

    //  Wait until ZAP handler terminates
    zmq_threadclose (zap_thread);

    return 0;
}
