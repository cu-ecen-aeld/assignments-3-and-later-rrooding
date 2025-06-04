#include <stdio.h>
#include <syslog.h>

int main(int argc, char *argv[]) {
    openlog("writer", LOG_CONS | LOG_PID, LOG_USER);

    if (argc != 3) {
        syslog(LOG_ERR, "writer expects 2 arguments: ./writer <writefile> <writestr>");
        closelog();
        return 1;
    }

    char *writefile = argv[1];
    char *writestr = argv[2];

    FILE *file = fopen(writefile, "w");

    if (file == NULL) {
        syslog(LOG_ERR, "failed to open file %s", writefile);
        closelog();
        return 1;
    }

    syslog(LOG_DEBUG, "Writing %s to %s", writestr, writefile);

    fprintf(file, "%s", writestr);

    fclose(file);
    closelog();
    
    return 0;
}