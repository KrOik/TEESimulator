// Fork-based supervisor for instant daemon restart
#include <unistd.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

static volatile sig_atomic_t should_exit = 0;

static void signal_handler(int sig) {
    should_exit = 1;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <daemon> [args...]\n", argv[0]);
        return 1;
    }

    if (argv[1] == nullptr) {
        fprintf(stderr, "Error: daemon path argument is null\n");
        return 1;
    }

    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);

    const char *daemon_path = argv[1];
    if (daemon_path[0] == '\0') {
        fprintf(stderr, "Error: daemon path is empty\n");
        return 1;
    }

    char **daemon_argv = &argv[1];

    while (!should_exit) {
        pid_t pid = fork();

        if (pid < 0) {
            perror("fork failed");
            usleep(100000);
            continue;
        }

        if (pid == 0) {
            prctl(PR_SET_PDEATHSIG, SIGKILL);
            execv(daemon_path, daemon_argv);
            perror("execv failed");
            _exit(127);
        }

        int status;
        waitpid(pid, &status, 0);

        if (should_exit) break;

        usleep(100000);
    }

    return 0;
}
