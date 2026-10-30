/* A stand-in for the Open Terminal server, small enough to build anywhere.
 *
 * tests/test_docker.py needs *an* image to put in a sandbox, and the official
 * one is four gigabytes.  This answers the handful of endpoints the proxy
 * relies on (/health, /api/config, /openapi.json, /system, /execute) and
 * nothing else.
 *
 * Built statically and imported as a scratch image, so the container holds this
 * single binary -- which also makes the isolation checks unambiguous: whatever
 * the sandbox can reach, it reached with this.
 *
 * Two modes, by argument count:
 *   fakeot                      serve HTTP on :8000
 *   fakeot <host> <port> ...    try to connect to each pair and report
 *
 * Build: gcc -static -O2 -o fakeot fake_terminal.c
 */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#define PORT 8000
#define BUFSZ 65536

static const char *API_KEY_ENV = "OPEN_TERMINAL_API_KEY";

static int probe(const char *ip, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons((unsigned short)port);
    if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) { close(fd); errno = EINVAL; return -1; }
    fcntl(fd, F_SETFL, O_NONBLOCK);
    if (connect(fd, (struct sockaddr *)&addr, sizeof addr) == 0) { close(fd); return 0; }
    if (errno != EINPROGRESS) { int saved = errno; close(fd); errno = saved; return -1; }
    fd_set writable;
    FD_ZERO(&writable);
    FD_SET(fd, &writable);
    struct timeval timeout = {3, 0};
    int ready = select(fd + 1, NULL, &writable, NULL, &timeout);
    if (ready <= 0) { close(fd); errno = ETIMEDOUT; return -1; }
    int error = 0;
    socklen_t length = sizeof error;
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length);
    close(fd);
    if (error) { errno = error; return -1; }
    return 0;
}

static void send_all(int fd, const char *data, size_t length) {
    size_t sent = 0;
    while (sent < length) {
        ssize_t wrote = write(fd, data + sent, length - sent);
        if (wrote <= 0) return;
        sent += (size_t)wrote;
    }
}

static void respond(int fd, int status, const char *reason, const char *body) {
    char header[512];
    int header_length = snprintf(header, sizeof header,
        "HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n",
        status, reason, strlen(body));
    send_all(fd, header, (size_t)header_length);
    send_all(fd, body, strlen(body));
}

/* Case-insensitive search for a header value. */
static int has_bearer(const char *request, const char *key) {
    const char *cursor = request;
    char wanted[512];
    snprintf(wanted, sizeof wanted, "Bearer %s", key);
    while (*cursor) {
        if (strncasecmp(cursor, "authorization:", 14) == 0) {
            cursor += 14;
            while (*cursor == ' ') cursor++;
            return strncmp(cursor, wanted, strlen(wanted)) == 0;
        }
        const char *next = strchr(cursor, '\n');
        if (!next) break;
        cursor = next + 1;
    }
    return 0;
}

static int serve(void) {
    signal(SIGPIPE, SIG_IGN);
    const char *api_key = getenv(API_KEY_ENV);
    if (!api_key) api_key = "";

    int listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0) { perror("socket"); return 1; }
    int one = 1;
    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(PORT);
    if (bind(listener, (struct sockaddr *)&addr, sizeof addr) < 0) { perror("bind"); return 1; }
    if (listen(listener, 64) < 0) { perror("listen"); return 1; }
    fprintf(stdout, "fake open terminal listening on :%d\n", PORT);
    fflush(stdout);

    char request[BUFSZ];
    for (;;) {
        int client = accept(listener, NULL, NULL);
        if (client < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            return 1;
        }
        ssize_t got = read(client, request, sizeof request - 1);
        if (got <= 0) { close(client); continue; }
        request[got] = '\0';

        char method[16] = {0}, path[1024] = {0};
        sscanf(request, "%15s %1023s", method, path);
        char *query = strchr(path, '?');
        if (query) *query = '\0';

        if (strcmp(path, "/health") == 0) {
            respond(client, 200, "OK", "{\"status\":\"ok\"}");
        } else if (strcmp(path, "/api/config") == 0) {
            respond(client, 200, "OK",
                "{\"features\":{\"terminal\":true,\"notebooks\":false,\"system\":true}}");
        } else if (strcmp(path, "/openapi.json") == 0) {
            respond(client, 200, "OK",
                "{\"openapi\":\"3.1.0\",\"info\":{\"title\":\"Open Terminal\",\"version\":\"fake\"},"
                "\"paths\":{\"/execute\":{\"post\":{\"operationId\":\"run_command\"}}}}");
        } else if (*api_key && !has_bearer(request, api_key)) {
            respond(client, 401, "Unauthorized", "{\"detail\":\"Invalid API key\"}");
        } else if (strcmp(path, "/system") == 0) {
            respond(client, 200, "OK", "{\"prompt\":\"fake sandbox\"}");
        } else if (strcmp(path, "/execute") == 0) {
            respond(client, 200, "OK", "{\"id\":\"p1\",\"status\":\"completed\",\"exit_code\":0}");
        } else if (strcmp(path, "/whoami") == 0) {
            char body[256];
            snprintf(body, sizeof body, "{\"uid\":%d,\"gid\":%d}", (int)getuid(), (int)getgid());
            respond(client, 200, "OK", body);
        } else {
            respond(client, 404, "Not Found", "{\"detail\":\"not found\"}");
        }
        close(client);
    }
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--mountinfo") == 0) {
        /* Used once, to confirm that a container can find its own id this way. */
        FILE *handle = fopen("/proc/self/mountinfo", "r");
        if (!handle) return 1;
        char line[4096];
        while (fgets(line, sizeof line, handle)) fputs(line, stdout);
        fclose(handle);
        return 0;
    }
    if (argc < 3) return serve();
    for (int index = 1; index + 1 < argc; index += 2) {
        errno = 0;
        int result = probe(argv[index], atoi(argv[index + 1]));
        printf("%s:%s %s (%s)\n", argv[index], argv[index + 1],
               result == 0 ? "REACHABLE" : "blocked", result == 0 ? "-" : strerror(errno));
        fflush(stdout);
    }
    return 0;
}
