#include <stdlib.h>
#include <dirent.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <string.h>
#include <ctype.h>
#include <pwd.h>
#include <inttypes.h>
#include <fcntl.h>
#include <time.h>

#pragma clang diagnostic push
#pragma ide diagnostic ignored "EndlessLoop"

#define HARDCODED_OWN_PROCESS_NAME "ProcessTracker"
#define DEBUG_MODE 0

#define UPDATE_RATE ((uint64_t) (1000 * 1000 * 1000))
#define SAVE_RATE ((uint64_t) (1000 * 1000 * 1000) * 15) // Save the stats in 15 second intervals

char data_directory[512];

/*
 * DIR/config: contains all process executable names to be tracked seperated by newlines
 * DIR/EXE_NAME/stats: contains everything in proc_track_t
 * DIR/EXE_NAME/sessions/: contains files with started_timestamp. Each file contains only the end timestamp
 *
 */

typedef struct {
    // Not saved
    int running; // Is the process currently running
    int save_flag; // Changes to 1 whenever the struct needs saving and to 0 after it's saved
    int found_flag; // Internal flag for update_process_stats. Is 1 if the process was found at least once, otherwise 0

    // Saved, either once or updated often
    char exe_name[512];
    uint64_t started_timestamp; // volatile
    uint64_t stopped_timestamp; // volatile
    uint64_t first_added_timestamp;
    uint64_t first_started_timestamp;
    uint64_t runs; // How many times the program started
    uint64_t runtime; // How many nanoseconds the program has been running in total, volatile
} proc_track_t;

int amount_processes;
proc_track_t *tracked_processes;

void print_errno() {
    fprintf(stderr, "Error code %d: %s\n", errno, strerror(errno));
}

long nanos(int mode) {
    struct timespec spec;
    if (clock_gettime(mode, &spec) == -1) return 0;
    return spec.tv_sec * 1000000000L + spec.tv_nsec;
}

int parse_ull(char *input, uint64_t *result) {
    char *ptr;
    *result = strtoull(input, &ptr, 10);
    if (ptr == input || *ptr != '\0') {
        return -1;
    }

    return 0;
}

void print_duration(char *result, size_t maxlen, uint64_t duration) {
    duration /= 1000 * 1000 * 1000; // convert nano seconds to seconds

    uint64_t hours = duration / 3600;
    duration %= 3600;

    uint64_t minutes = duration / 60;
    duration %= 60;

    uint64_t seconds = duration;

    snprintf(result, maxlen,
             "%02lu:%02lu:%02lu",
             hours,
             minutes,
             seconds
    );
}

char* strip_proc_name(char *string) {
    char *new_string = string;
    for (int str_index = 0; string[str_index] != '\0'; str_index++) {
        if (string[str_index] == '/') {
            new_string = string + str_index + 1;
        }
    }
    return new_string;
}

// ToDo: Make this function better
void get_home_dir(char *output, size_t output_n) {
    struct passwd pwd;
    struct passwd *result;
    char *buf;
    size_t bufsize;
    int s;
    bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
    if (bufsize == -1)
        bufsize = 0x4000; // = all zeroes with the 14th bit set (1 << 14)
    buf = malloc(bufsize);
    if (buf == NULL) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }
    s = getpwuid_r(getuid(), &pwd, buf, bufsize, &result);
    if (result == NULL) {
        if (s == 0)
            printf("Not found\n");
        else {
            errno = s;
            perror("getpwnam_r");
        }
        exit(EXIT_FAILURE);
    }
    snprintf(output, output_n, "%s/.local/share/process-tracker", result->pw_dir); // result->pw_dir is usually "/home/USERNAME"
    free(buf);
}

int contains_non_digits(char *string) {
    char *c = string;
    while (*c != '\0') {
        if (!isdigit(*c)) {
            return 1;
        }

        c++;
    }
    return 0;
}

pid_t proc_find(const char *name, long pid) {
    DIR *dir;
    struct dirent *ent;
    char *endptr;

    if (!(dir = opendir("/proc"))) {
        perror("can't open /proc");
        return -1;
    }

    pid_t found_pid = -1;
    while ((ent = readdir(dir)) != NULL) {
        /* if endptr is not a null character, the data_directory is not
         * entirely numeric, so ignore it */
        pid_t lpid = (int) strtol(ent->d_name, &endptr, 10);
        if (*endptr != '\0') {
            continue;
        }

        char proc_exe_filename[512];
        char proc_exe_str[512];

        snprintf(proc_exe_filename, sizeof proc_exe_filename - 1, "/proc/%d/exe", lpid);

        long bytes_read = readlink(proc_exe_filename, proc_exe_str, sizeof proc_exe_str - 1);
        if (bytes_read < 0) continue;

        proc_exe_str[bytes_read] = '\0';

        char *proc_str = strip_proc_name(proc_exe_str);

        if (!strcmp(proc_str, name)) {
            if (pid > 0 && pid == lpid) continue; // If pid > 0, only return lpid if it is different from pid
            found_pid = lpid;
            break;
        }
    }

    closedir(dir);
    return found_pid;
}

void save_stats() {
    int save_attempts = 0, save_successes = 0;
    for (int i = 0; i < amount_processes; i++) {
        proc_track_t *tracked_process = &tracked_processes[i];
        if (!tracked_process->save_flag) continue;
        tracked_process->save_flag = 0;

        save_attempts++;

        char proc_directory[512];
        snprintf(proc_directory, sizeof proc_directory - 1, "%s/%s", data_directory, tracked_process->exe_name);

        char proc_filename[512];
        snprintf(proc_filename, sizeof proc_filename - 1, "%s/stats", proc_directory);
        int proc_file = open(proc_filename, O_WRONLY | O_TRUNC | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);

        if (proc_file < 1) {
            fprintf(stdout, "Failed to open process stats %s, attempting to create directory\n", proc_filename);
            print_errno();

            int mkdir_err = mkdir(proc_directory, S_IFDIR | S_IRWXU | S_IRWXG);
            if (mkdir_err != 0) {
                fprintf(stderr, "Failed to create process directory %s\n", proc_directory);
                print_errno();
                continue;
            }

            proc_file = open(proc_filename, O_WRONLY | O_TRUNC | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
            if (proc_file < 1) {
                fprintf(stderr, "Failed to open process stats for %s again\n", tracked_process->exe_name);
                print_errno();
                continue;
            }
        }

        char file_content[1024];
        snprintf(file_content, sizeof file_content - 1,
                 "%s\n"
                 "%lu\n"
                 "%lu\n"
                 "%lu\n"
                 "%lu\n"
                 "%lu\n"
                 "%lu\n",
                 tracked_process->exe_name,
                 tracked_process->started_timestamp,
                 tracked_process->stopped_timestamp,
                 tracked_process->first_added_timestamp,
                 tracked_process->first_started_timestamp,
                 tracked_process->runs,
                 tracked_process->runtime
        );

        long bytes_written = write(proc_file, file_content, strnlen(file_content, sizeof file_content - 1));
        close(proc_file);

        if (bytes_written < 1) {
            fprintf(stderr, "Failed to write process stats to %s\n", proc_filename);
            print_errno();
            continue;
        }

        char session_directory[512];
        snprintf(session_directory, sizeof session_directory - 1, "%s/sessions", proc_directory);

        char session_filename[512];
        snprintf(session_filename, sizeof session_filename - 1, "%s/%lu.session", session_directory, tracked_process->started_timestamp);
        int session_file = open(session_filename, O_WRONLY | O_TRUNC | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);

        if (session_file < 1) {
            fprintf(stderr, "Failed to open session file %s, attempting to create directory\n", session_filename);
            print_errno();

            int mkdir_err = mkdir(session_directory, S_IFDIR | S_IRWXU | S_IRWXG);
            if (mkdir_err != 0) {
                fprintf(stderr, "Failed to create session directory %s\n", session_directory);
                print_errno();
                continue;
            }

            session_file = open(session_filename, O_WRONLY | O_TRUNC | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
            if (session_file < 1) {
                fprintf(stderr, "Failed to open session file %s again\n", session_filename);
                print_errno();
                continue;
            }
        }

        bytes_written = write(session_file, file_content, strnlen(file_content, sizeof file_content - 1));
        close(session_file);

        if (bytes_written < 1) {
            fprintf(stderr, "Failed to write session to %s\n", session_filename);
            print_errno();
            continue;
        }

        save_successes++;
    }

    if (save_attempts != save_successes) {
        fprintf(stderr, "%d process%s failed to save!\n", save_attempts - save_successes, (save_attempts - save_successes) == 1 ? "" : "es");
        // ToDo: Exit program?
    }

    printf("Saved %d/%d process%s\n", save_successes, save_attempts, (save_successes) == 1 ? "" : "es");
}

/*
 * RETURN VALUES:
 * 1: If a new process started or stopped
 * 0: The same processes are running as last time
 */
int update_process_stats() {
    int result = 0;
    uint64_t now = nanos(CLOCK_REALTIME);

    DIR *dir;
    struct dirent *proc_dir_entry;

    if (!(dir = opendir("/proc"))) {
        fprintf(stderr, "Can't read /proc\n");
        print_errno();
        exit(EXIT_FAILURE);
    }

    int proc_entry_count = 0;
    while ((proc_dir_entry = readdir(dir)) != NULL) {
        proc_entry_count++;
        if (contains_non_digits(proc_dir_entry->d_name)) continue;

        uint64_t pid;
        int parse_result = parse_ull(proc_dir_entry->d_name, &pid);
        if (parse_result == -1) {
            fprintf(stderr, "Couldn't parse PID from %s\n", proc_dir_entry->d_name);
            print_errno();
            continue;
        }

        char proc_exe_filename[512];
        char proc_exe_str[512];

        snprintf(proc_exe_filename, sizeof proc_exe_filename - 1, "/proc/%lu/exe", pid);

        long bytes_read = readlink(proc_exe_filename, proc_exe_str, sizeof proc_exe_str - 1);
        if (bytes_read < 0) continue;

        proc_exe_str[bytes_read] = '\0';

        char *proc_str = strip_proc_name(proc_exe_str);

        for (int i = 0; i < amount_processes; i++) {
            if (strcmp(tracked_processes[i].exe_name, proc_str) == 0) {
                proc_track_t *process = &tracked_processes[i];
                process->found_flag = 1; // Mark as found
            }
        }
    }
    closedir(dir);
    printf("Scanned %d process entries\n", proc_entry_count);

    // Iterate through all running processes
    for (int i = 0; i < amount_processes; i++) {
        proc_track_t *process = &tracked_processes[i];
        if (!process->found_flag) continue;
        process->found_flag = 0;

        process->save_flag = 1;

        printf("Found running process: %s\n", process->exe_name);

        if (process->running) { // Process is already registered as running. Update the runtime and save it
            process->runtime += now - process->stopped_timestamp;
            process->stopped_timestamp = now;
        } else { // Process isn't running and needs to be properly initialized as running
            result = 1;
            process->running = 1;
            process->started_timestamp = now;
            process->stopped_timestamp = now;

            if (process->first_started_timestamp == 0) process->first_started_timestamp = now;
        }
    }

    // Iterate through all tracked processes
    for (int i = 0; i < amount_processes; i++) {
        proc_track_t *process = &tracked_processes[i];
        if (process->running) {
            if (process->stopped_timestamp != now) { // Process marked as running but wasn't found in the iteration which just ran. Therefore, the process must have closed
                result = 1;
                process->save_flag = 1;

                process->running = 0;
                process->runs++;

                char duration_str[32];
                print_duration(duration_str, sizeof duration_str - 1, process->stopped_timestamp - process->started_timestamp);

                printf("%s stopped after %s\n", process->exe_name, duration_str);
            }
        }
    }

    return result;
}

void print_running() {
    update_process_stats();

    printf("================ Currently running processes ================\n");
    int first = 1;
    for (int i = 0; i < amount_processes; i++) {
        proc_track_t *tracked_process = &tracked_processes[i];
        if (!tracked_process->running) continue;
        if (first) {
            first = 0;
        } else {
            printf(", ");
        }
        printf("%s", tracked_process->exe_name);
    }
    printf("\n");
    printf("=============================================================\n");
}

void initialize(int argc, char **argv) {
    int print_running_and_exit = 0;
    // If argv[1] is "list" or if another instance is already running, print the currently running/tracked processes and exit
    if ((argc >= 2 && strcmp(argv[1], "list") == 0)) {
        printf("Listing processes and exiting\n");
        print_running_and_exit = 1;
    }

    pid_t pid = proc_find(HARDCODED_OWN_PROCESS_NAME, getpid());
    if (pid > 0) {
        printf("Found another instance already running with PID %d\n", pid);
        print_running_and_exit = 1;
    }

    // Set home data_directory
    get_home_dir(data_directory, sizeof data_directory);

    // Read config file with processes to be tracked
    char config_filename[512];
    snprintf(config_filename, sizeof config_filename - 1, "%s/config", data_directory);
    int config_file = open(config_filename, O_RDWR);
    if (config_file < 1) {
        fprintf(stderr, "Couldn't open %s\n", config_filename);
        print_errno();
        printf("Creating new config file\n");

        int mkdir_err = mkdir(data_directory, S_IFDIR | S_IRWXU | S_IRWXG);
        if (mkdir_err != 0) {
            fprintf(stderr, "Failed to create data_directory %s\n", data_directory);
            exit(EXIT_FAILURE);
        }
        config_file = open(config_filename,
                           O_RDWR | O_CREAT,
                           S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
        if (config_file < 1) {
            fprintf(stderr, "Failed to create new config file %s\n", config_filename);
            print_errno();
            exit(EXIT_FAILURE);
        }
    }

    // Get config file size
    struct stat config_file_stats;
    int code = stat(config_filename, &config_file_stats);
    if (code != 0) {
        fprintf(stderr, "Failed to get config file size %s\n", config_filename);
        exit(EXIT_FAILURE);
    }

    long bytes_to_read = config_file_stats.st_size;
    if (bytes_to_read >
        0x7ffff000) { // Only 0x7ffff000 bytes can be read at once via the read() system call, the config file will never get to that size anyway
        fprintf(stderr, "Config file is too big to be read (%ld bytes)\n", bytes_to_read);
        exit(EXIT_FAILURE);
    }

    // Allocate memory for config file string
    char *config_str = malloc(bytes_to_read + 1); // Don't forget the '\0' terminator

    long bytes_read = read(config_file, config_str, bytes_to_read);
    close(config_file);
    if (bytes_read < 0) {
        fprintf(stderr, "Error while reading file %s\n", config_filename);
        print_errno();
        exit(EXIT_FAILURE);
    }

    if (bytes_read != bytes_to_read) {
        fprintf(stderr, "Expected %ld bytes but got %ld instead\n", bytes_to_read, bytes_read);
        exit(EXIT_FAILURE);
    }

    config_str[bytes_read] = '\0'; // Set '\0' terminator to mark end of config string

    /* Do stuff with config string here */

    // Every line is one tracked process
    int processes = 0;
    char *proc_name;

    char *config_str_ptr = config_str;
    for (; (proc_name = strtok_r(config_str_ptr, "\n", &config_str_ptr)) != NULL; processes++) {
        printf("Found config process to track: <%s>\n", proc_name);

        // ToDo: Allocate memory only once
        tracked_processes = realloc(tracked_processes, (processes + 1) * sizeof(proc_track_t));
        if (tracked_processes == NULL) {
            fprintf(stderr, "realloc() failed\n");
            exit(EXIT_FAILURE);
        }

        proc_track_t *tracked_process = &tracked_processes[processes];
        memset(tracked_process, 0, sizeof(proc_track_t));

        tracked_process->running = 0;
        strncpy(tracked_process->exe_name, proc_name, sizeof tracked_process->exe_name - 1);

        // Check if a stat file already exists for that process
        char proc_filename[512];
        snprintf(proc_filename, sizeof proc_filename - 1, "%s/%s/stats", data_directory, proc_name);
        int proc_file = open(proc_filename, O_RDONLY);

        if (proc_file > 0) {
            // Get config file size
            struct stat proc_file_stats;
            code = stat(proc_filename, &proc_file_stats);
            if (code != 0) {
                fprintf(stderr, "Failed to get proc file size %s\n", proc_filename);
                exit(EXIT_FAILURE);
            }

            bytes_to_read = proc_file_stats.st_size;
            if (bytes_to_read > 0x7ffff000) {
                fprintf(stderr, "Proc file is too big to be read (%ld bytes)\n", bytes_to_read);
                exit(EXIT_FAILURE);
            }

            char *proc_str = malloc(bytes_to_read + 1);

            bytes_read = read(proc_file, proc_str, bytes_to_read);
            close(proc_file);
            if (bytes_read < 0) {
                fprintf(stderr, "Error while reading file %s\n", proc_filename);
                print_errno();
                exit(EXIT_FAILURE);
            }

            if (bytes_read != bytes_to_read) {
                fprintf(stderr, "Expected %ld bytes but got %ld instead\n", bytes_to_read, bytes_read);
                exit(EXIT_FAILURE);
            }

            proc_str[bytes_read] = '\0';

            int i = 0;
            char *current_line = proc_str;
            for (; current_line; i++) {
                char *next_line = strchr(current_line, '\n'); // String \n split control flow
                if (next_line) *next_line = '\0'; // String \n split control flow

                printf("LINE %s\n", current_line);
                if (i == 0) {
                    if (strcmp(current_line, proc_name) != 0) {
                        fprintf(stderr, "Proc file doesn't contain its directory's proc exe_name name\n");
                        //exit(EXIT_FAILURE);
                    }
                }

                uint64_t *ull_ptr = NULL;
                switch (i) {
                    case 0:
                        break;
                    case 1:
                        ull_ptr = &tracked_process->started_timestamp;
                        break;
                    case 2:
                        ull_ptr = &tracked_process->stopped_timestamp;
                        break;
                    case 3:
                        ull_ptr = &tracked_process->first_added_timestamp;
                        break;
                    case 4:
                        ull_ptr = &tracked_process->first_started_timestamp;
                        break;
                    case 5:
                        ull_ptr = &tracked_process->runs;
                        break;
                    case 6:
                        ull_ptr = &tracked_process->runtime;
                        break;
                    default:
                        break;
                }

                if (ull_ptr != NULL) {
                    code = parse_ull(current_line, ull_ptr);
                    if (code != 0) {
                        fprintf(stderr, "Failed to parse integer %s from %s\n", current_line, proc_filename);
                        exit(EXIT_FAILURE);
                    }
                }

                current_line = next_line ? (next_line + 1) : NULL; // String \n split control flow
            }

            char file_content[1024];
            snprintf(file_content, sizeof file_content - 1,
                     "%s\n"
                     "%lu\n"
                     "%lu\n"
                     "%lu\n"
                     "%lu\n"
                     "%lu\n"
                     "%lu\n",
                     tracked_process->exe_name,
                     tracked_process->started_timestamp,
                     tracked_process->stopped_timestamp,
                     tracked_process->first_added_timestamp,
                     tracked_process->first_started_timestamp,
                     tracked_process->runs,
                     tracked_process->runtime
            );

            printf("%s", file_content);
            free(proc_str);
        } else {
            fprintf(stderr, "Found no stats for %s\n", proc_filename);
        }
    }
    free(config_str); // Free the config string memory

    amount_processes = processes;

    if (print_running_and_exit) {
        print_running();
        exit(EXIT_SUCCESS);
    }
}

int main(int argc, char *argv[]) {
    initialize(argc, argv);

    uint64_t current_time;
    uint64_t next_update = nanos(CLOCK_MONOTONIC) + UPDATE_RATE;
    uint64_t next_save = next_update;
    while (1) {
        int sleeps = 0;
        while (next_update > (current_time = nanos(CLOCK_MONOTONIC))) {
            sleeps++;
            int sleep_amount = (int) ((next_update - current_time) / 1000);
            usleep(sleep_amount);
        }
        // printf("Missed exact timestamp by %.2f nanoseconds using %d sleep calls\n", (float) (current_time - next_update), sleeps);
        next_update += UPDATE_RATE;

        uint64_t before = nanos(CLOCK_MONOTONIC);
        int result = update_process_stats();
        if (result || before >= next_save) { // Save stats only if update_process_stats requests it (process started/stopped) OR if enough time has passed
            next_save += SAVE_RATE;
            save_stats();
        }
        uint64_t after = nanos(CLOCK_MONOTONIC);
        printf("Took %.2f milliseconds to update process stats\n", (float) (after - before) / (1e6));
    }

    return EXIT_SUCCESS;
}

#pragma clang diagnostic pop
