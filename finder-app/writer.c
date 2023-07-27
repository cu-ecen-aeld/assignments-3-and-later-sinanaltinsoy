#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>

int main(int argc, char *argv[]) {
  if (argc != 3) {
    fprintf(stderr, "Usage: %s <textString> <file>\n", argv[0]);
    return 1;
  }

  openlog("writer", LOG_PID, LOG_USER);

  const char *text_string = argv[2];
  const char *file_path = argv[1];

  FILE *file = fopen(file_path, "w");
  if (file == NULL) {
    syslog(LOG_ERR, "Error opening file: %s", file_path);
    perror("Error");
    return 1;
  }

  if (fprintf(file, "%s", text_string) < 0) {
    syslog(LOG_ERR, "Error writing to file: %s", file_path);
    perror("Error");
    fclose(file);
    return 1;
  }

  fclose(file);
  syslog(LOG_DEBUG, "Writing '%s' to %s", text_string, file_path);

  closelog();

  return 0;
}