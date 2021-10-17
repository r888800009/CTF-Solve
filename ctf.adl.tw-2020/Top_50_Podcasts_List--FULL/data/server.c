#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <errno.h>
#define ERRNOSTR    strerror(errno)
#define MAXNAME     77
#define MAXURL      51
#define MAXPLATF    20
#define MAXRANKNUM  5

/*
 * A podcast metadata query server written by davidhcefx.
 */

struct Rank {
    char platform[MAXPLATF];
    int num;
};

struct Podcast {
    char name[MAXNAME];
    char url[MAXURL];
    struct Rank* ranks[MAXRANKNUM + 1];  // NULL terminated
};

struct Podcast** podcasts;  // NULL terminated
char* line = NULL;  // storage for getline
size_t maxlen = 0;


// strip blanks from str and return str
char* strip(char* str) {
    int i;
    // strip front
    while (*str != '\0' && isspace(*str)) {
        str++;
    }
    // strip back
    for (i = 0; str[i] != '\0'; i++) {}
    i--;
    for ( ; i >= 0 && isspace(str[i]); i--) {}
    str[i + 1] = '\0';

    return str;
}

void strcpy_safe(char* dest, const char* src, int len) {
    if (dest == NULL || src == NULL || len < 0) return;
    memcpy(dest, src, len);
}

struct Podcast* find_with_name(const char* name) {
    int i;
    for (i = 0; podcasts[i] != NULL; i++) {
        if (strcmp(name, podcasts[i]->name) == 0) {
            return podcasts[i];
        }
    }
    return NULL;
}

struct Podcast* find_with_url(const char* url) {
    int i;
    for (i = 0; podcasts[i] != NULL; i++) {
        if (strcmp(url, podcasts[i]->url) == 0) {
            return podcasts[i];
        }
    }
    return NULL;
}

void handle_client() {
    struct Podcast* pcast;
    char url[MAXURL];
    char name[MAXNAME];
    int i;

    while (getline(&line, &maxlen, stdin) > 1) {
        if (strncmp(line, "list", 4) == 0) {
            // list
            for (i = 0; podcasts[i] != NULL; i++) {
                puts(podcasts[i]->name);
            }
        } else if (strncmp(line, "info", 4) == 0) {
            // info [name]
            strcpy_safe(name, line + 4, MAXNAME);
            pcast = find_with_name(strip(name));
            if (pcast == NULL) {
                fprintf(stderr, name);
                exit(1);
            }
            puts(pcast->name);
            for (i = 0; pcast->ranks[i] != NULL; i++) {
                printf("%d ", pcast->ranks[i]->num);
                puts(pcast->ranks[i]->platform);
            }
        } else if (strncmp(line, "link", 4) == 0) {
            // link [name]
            strcpy_safe(name, line + 4, MAXNAME);
            pcast = find_with_name(strip(name));
            if (pcast != NULL) {
                puts(pcast->url);
            }
        } else if (strncmp(line, "nameof", 6) == 0) {
            // nameof [url]
            strcpy_safe(url, line + 6, MAXNAME);
            pcast = find_with_url(strip(url));
            if (pcast != NULL) {
                puts(pcast->name);
            }
        }
    }
}

void freadline_to(FILE* file, char* buf, int n) {
    int len = getline(&line, &maxlen, file);
    line[len - 1] = '\0';   // remove newline
    strcpy_safe(buf, line, n);
}

void load_database() {
    FILE* file;
    int i, j, value, num_line;
    struct Podcast* pcast;

    if ((file = fopen("podcasts.list", "r")) == NULL) {
        fprintf(stderr, "Can't open file: %s\n", ERRNOSTR);
        exit(1);
    }
    puts("Loading database...");

    fscanf(file, "%d ", &num_line);
    podcasts = malloc((num_line + 1) * sizeof(struct Podcast*));
    podcasts[num_line] = NULL;  // be sure to NULL-terminate it!

    for (i = 0; i < num_line; i++) {
        pcast = podcasts[i] = malloc(sizeof(struct Podcast));
        freadline_to(file, pcast->name, MAXNAME);
        freadline_to(file, pcast->url, MAXURL);
        j = 0;
        while (fscanf(file, "- %d ", &value) > 0) {  // read all ranks
            if (j < MAXRANKNUM) {
                pcast->ranks[j] = malloc(sizeof(struct Rank));
                pcast->ranks[j]->num = value;
                freadline_to(file, pcast->ranks[j]->platform, MAXPLATF);
                j++;
            } else {
                getline(&line, &maxlen, file);
            }
        }
        pcast->ranks[j] = NULL;  // don't forget to NULL-terminate it!
        puts(pcast->name);
    }
    puts("Done.\n");
    fclose(file);
}

int passiveTCP(short port) {
    struct sockaddr_in addr;
    int sockFd;

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if ((sockFd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        fprintf(stderr, "Can't create socket: %s\n", ERRNOSTR);
        exit(1);
    }
    if (bind(sockFd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "Can't bind to port %d: %s\n", port, ERRNOSTR);
        exit(1);
    }
    if (listen(sockFd, 0) < 0) {
        fprintf(stderr, "Can't listen: %s\n", ERRNOSTR);
        exit(1);
    }
    printf("Pid %d listening on port %d...\n", getpid(), port);
    return sockFd;
}

void child_reaper(int sig) {
    int stat;
    while (wait3(&stat, WNOHANG, 0) > 0) {
        printf("Child exited: %d\n", stat);
    }
}

void init() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    signal(SIGCHLD, child_reaper);
    load_database();
}

int main(int argc, char* argv[]) {
    struct sockaddr_in c_addr;
    socklen_t c_addr_len = sizeof(c_addr);
    int m_sock, s_sock, pid, port = 11007;

    if (argc > 1) {
        port = atoi(argv[1]);
    }
    init();
    m_sock = passiveTCP(port);

    while (1) {
        s_sock = accept(m_sock, (struct sockaddr*)&c_addr, &c_addr_len);
        printf("Connected: %s, %d\n", inet_ntoa(c_addr.sin_addr), ntohs(c_addr.sin_port));

        if ((pid = fork()) < 0) {
            fprintf(stderr, "Can't fork: %s\n", ERRNOSTR);
        } else if (pid == 0) {
            close(m_sock);
            // redirection
            dup2(s_sock, 0);
            dup2(s_sock, 1);
            dup2(s_sock, 2);
            close(s_sock);
            // timer
            signal(SIGALRM, exit);
            alarm(60);
            handle_client();
            exit(0);
        }
        close(s_sock);
    }
    return 0;
}
