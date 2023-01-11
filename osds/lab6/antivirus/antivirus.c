#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/inotify.h>
#include <unistd.h>
#include <string.h>
#include <curl/curl.h>

#include "../sha256/sha-256.h"


#define EVENT_SIZE  ( sizeof ( struct inotify_event ) )
#define EVENT_BUF_LEN     ( 1024 * ( EVENT_SIZE + 16 ) )


char *compute_sha(const char* file_path) {
    FILE * f = NULL;
    unsigned int i = 0;
    unsigned int j = 0;
    char buf[4096];
    uint8_t sha256sum[32];
    if ( !( f = fopen( file_path, "rb" ) ) ) {
        perror( "fopen" );
        return NULL;
    }
    
    sha256_context ctx;
    sha256_starts( &ctx );

    while( ( i = fread( buf, 1, sizeof( buf ), f ) ) > 0 )
    {
        sha256_update( &ctx, (uint8_t*) buf, i );
    }
    sha256_finish( &ctx, sha256sum );

    char *out = calloc(65, sizeof(*out));
    for( j = 0; j < 32; j++ ) {
        sprintf( out + j * 2, "%02x", sha256sum[j] );
    }
    return out;
}

struct string {
  char *ptr;
  size_t len;
};

void init_string(struct string *s) {
  s->len = 0;
  s->ptr = malloc(s->len+1);
  if (s->ptr == NULL) {
    fprintf(stderr, "malloc() failed\n");
    exit(EXIT_FAILURE);
  }
  s->ptr[0] = '\0';
}

size_t write_callback(void *ptr, size_t size, size_t nmemb, struct string *s) {
  size_t new_len = s->len + size*nmemb;
  s->ptr = realloc(s->ptr, new_len+1);
  if (s->ptr == NULL) {
    fprintf(stderr, "realloc() failed\n");
    exit(EXIT_FAILURE);
  }
  memcpy(s->ptr+s->len, ptr, size*nmemb);
  s->ptr[new_len] = '\0';
  s->len = new_len;

  return size*nmemb;
}


void skip_n_chars(int n, const char t, int *i, const char *s) {
    while (n) {
        if (s[*i] == t) {
            n -= 1;
        }
        *i += 1;
    }
}

int32_t parse_response_get_malicious_votes(const char* s) {
    int skip_brackets = 3;
    int skip_commas = 5;
    int skip_collons = 1;

    int i = 0;
    skip_n_chars(skip_brackets, ']', &i, s);
    skip_n_chars(skip_commas, ',', &i, s);
    skip_n_chars(skip_collons, ':', &i, s);

    int n = 0;
    while (s[i] < '0' || s[i] > '9')
        i += 1;

    while (s[i] >= '0' && s[i] <= '9') {
        n = n * 10 + s[i] - '0';
        i += 1;
    }

    return n;
}

int8_t get_danger_level(const char *file_hash) {
    CURL *curl;
    CURLcode res;

    struct string s;
    init_string(&s);

    const char* api_key = getenv("VT_API_KEY");
    if (api_key == NULL) {
        fprintf(stderr, "api key no found\n");
    }
    const char *vt_url = getenv("VT_URL");
    if (vt_url == NULL) {
        fprintf(stderr, "vt_url no found\n");
    }

    char header[200] = "x-apikey:";
    strcat(header, api_key);
    
    char url[200] = "";
    strcat(url, vt_url);
    strcat(url, file_hash);

    curl = curl_easy_init();

    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &s);

        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, header);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        /* Perform the request, res will get the return code */ 
        res = curl_easy_perform(curl);
        /* Check for errors */ 
        if (res != CURLE_OK) {
          fprintf(stderr, "curl_easy_perform() failed: %s\n",
                  curl_easy_strerror(res));
        } else {
            // Get the response code
            long response_code;
            res = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

            printf("status code: ");
            if((res == CURLE_OK) && (response_code == 200)) {
                printf("%ld\n", response_code);
                int k = parse_response_get_malicious_votes(s.ptr);
                printf("Reported as malicious by %d entities\n", k);
                return k;
            } else {
                printf("%ld\n", response_code);
            }
        }
 
        /* always cleanup */ 
        curl_easy_cleanup(curl);
    }

    return 0;
}

int main() {
  int length, i = 0;
  int fd;
  int wd;
  char buffer[EVENT_BUF_LEN];

  /*creating the INOTIFY instance*/
  fd = inotify_init();

  /*checking for error*/
  if ( fd < 0 ) {
    perror( "inotify init failed" );
  }

  /*adding the “/watch_folder” directory into watch list.
    Here, the suggestion is to validate the existence of
    the directory before adding into monitoring list.*/
  const char* watch_folder = "/home/stef/Documents/master/osds/lab6/watch_folder";
  wd = inotify_add_watch( fd, watch_folder, 
          IN_CREATE | IN_DELETE | IN_ACCESS );

  /*read to determine the event change happens on “/tmp” directory.
    Actually this read blocks until the change event occurs*/ 
  do {
	  i = 0;
      length = read( fd, buffer, EVENT_BUF_LEN ); 

      /*checking for error*/
      if ( length < 0 ) {
          perror( "read" );
      }  

      /*actually read return the list of change events happens.
        Here, read the change event one by one and process it accordingly.*/
      while ( i < length ) { 
          struct inotify_event *event = (struct inotify_event*) &buffer[i];
          if ( event->len ) {
              if ( event->mask & IN_ACCESS ) {
                  if ( event-> mask & IN_ISDIR ) {
                      printf( "Directory \"%s\" accessed\n", event->name );
                  } else {
                      printf( "File \"%s\" accessed.\n", event->name );
                  }
              }
              if ( event->mask & IN_CREATE ) {
                  if ( event->mask & IN_ISDIR ) {
                      printf( "New directory \"%s\" created.\n", event->name );
                  } else {
                      printf( "New file \"%s\" created.\n", event->name );

                      char file_path[100] = "/home/stef/Documents/"
                          "master/osds/lab6/watch_folder/";
                      strncat(file_path, event->name, strlen(event->name));

                      char *file_hash = compute_sha( file_path );
                      int8_t danger_level = get_danger_level(file_hash);

                      if (danger_level != 0) {
                          printf("Removing dangerous file...\n");
                          remove(file_path);
                      }

                      free(file_hash);
                  }
              }
              else if ( event->mask & IN_DELETE ) {
                  if ( event->mask & IN_ISDIR ) {
                      printf( "Directory \"%s\" deleted.\n", event->name );
                  } else {
                      printf( "File \"%s\" deleted.\n", event->name );
                  }
              }
          }
          i += EVENT_SIZE + event->len; // bewarry
      }
  } while (1);

  /*removing the “/watch_folder” directory from the watch list.*/
  inotify_rm_watch( fd, wd );

  /*closing the INOTIFY instance*/
  close( fd );
}
