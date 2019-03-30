/* Feel free to use this example code in any way
   you see fit (Public Domain) */

#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <string.h>
#include <microhttpd.h>
#include <pthread.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <libgen.h>
#include <linux/limits.h>
#include "l4d2query/l4d2query.h"

#define MOTD_HTML "motd.html"
#define PORT 91

int handle_svr_query(const char* addr, void** responce, size_t* len, int* memory_mode);

typedef struct _cached_resources CachedResources;
struct _cached_resources {
	CachedResources* nextNode;
	char* location;
	uint8_t* rawdata;
	size_t len;
};
static CachedResources* cachedresources = NULL;

/*
 *	Return file size in bytes
 */
static size_t get_file_size(const char* filename)
{
	struct stat st;
	if (stat(filename, &st) < 0)
		return 0;
	return st.st_size;
}

/*
 *	Check if the requested url is valid, if so, return 1, otherwise return 0.
 */
int is_valid_resource(const char* url, char* actual_loc, char* mime_type) {
	char url_copy[PATH_MAX], url_copy2[PATH_MAX];
	strcpy(url_copy, url);
	strcpy(url_copy2, url);
	char* url_dirname = dirname(url_copy);
	char* url_basename = basename(url_copy2);

	if (strcmp(url_dirname, "/") == 0) {
		if (strcmp(url_basename, "/") == 0) {
			//printf("Index Request!\n");
			strcpy(actual_loc, MOTD_HTML);
			strcpy(mime_type, "text/html");
			return 1;
		} else if (strcmp(url_basename, "motd.html") == 0) {
			//printf("Index Request!\n");
			strcpy(actual_loc, MOTD_HTML);
			strcpy(mime_type, "text/html");
			return 1;
		} else {
			return 0;
		}
	} else if (strcmp(url_dirname, "/img") == 0) {
		int url_basename_len = strlen(url_basename);
		if (	url_basename_len > 4 &&
			url_basename[url_basename_len-4] == '.' &&
			url_basename[url_basename_len-3] == 'j' &&
			url_basename[url_basename_len-2] == 'p' &&
			url_basename[url_basename_len-1] == 'g') {

			//printf("Image Request!\n");
			strcpy(actual_loc, url+1);
			strcpy(mime_type, "image/jpeg");
			return 1;
		} else {
			return 0;
		}
	}

	return 0;
}

CachedResources* get_cached_resource(const char* url, char* mime_type) {
	char actual_loc[PATH_MAX];
	if (!is_valid_resource(url, actual_loc, mime_type)) {
		printf("URL %s is invalid!\n", url);
		return NULL;
	}

	CachedResources* curNode = cachedresources;
	while (curNode != NULL) {
		if (strcmp(curNode->location, actual_loc) == 0)
			break;
		curNode = curNode->nextNode;
	}

	if (curNode == NULL) {
		// precache the requested data if it has not been
		CachedResources* newNode = 
			(CachedResources*) malloc(sizeof(CachedResources));
		if (newNode == NULL) {
			printf("Could not allocate memory for resource %s!\n", actual_loc);
			free(newNode);
			return NULL;
		}

		size_t res_len = get_file_size(actual_loc);
		if (res_len == 0) {
			printf("Resource %s has incorrect size!\n", actual_loc);
			free(newNode);
			return NULL;
		}

		newNode->rawdata = (uint8_t*) malloc(sizeof(char)*res_len);
		if (newNode->rawdata == 0) {
			printf("Unable to allocate memory for resource %s!\n", actual_loc);
			free(newNode);
			return NULL;
		}

		// Read the resource file in binary format
		FILE* pFile = fopen(actual_loc, "rb");
		if (pFile == NULL) {
			printf("Could not find resource %s!\n", actual_loc);
			free(newNode);
			return NULL;
		}

		newNode->len = fread(newNode->rawdata, 1, res_len, pFile);
		fclose(pFile);

		newNode->location = malloc(sizeof(char)*PATH_MAX);
		strcpy(newNode->location, actual_loc);

		newNode->nextNode = cachedresources;	// Insert at the front;	
		cachedresources = newNode; // Insert at the front;

		printf("Precached %s for URL %s, size = %ld.\n", actual_loc, url, newNode->len);
		return newNode;
	} else {
		printf("Found precached resource %s for URL %s.\n", actual_loc, url);
		return curNode;
	}
}

static int answer_to_connection (void *cls, struct MHD_Connection *connection,
                      const char *url, const char *method,
                      const char *version, const char *upload_data,
                      size_t *upload_data_size, void **con_cls)
{
	char mime_type[32];
	int memory_mode;
	void* payload;
	size_t len;
	if (strcmp(url, "/svrquery") == 0) {
		const char* addr = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "addr");
		if (addr == NULL)
			return MHD_NO;

		if (!handle_svr_query(addr, &payload, &len, &memory_mode))
			return MHD_NO;

		strcpy(mime_type, "text/html");
	} else {
		CachedResources* resource = get_cached_resource(url, mime_type);
		if (resource == NULL)
			return MHD_NO;

		payload = resource->rawdata;
		len = resource->len;
		memory_mode = MHD_RESPMEM_PERSISTENT;
	}


  	struct MHD_Response *response;
  	int ret;

	response = MHD_create_response_from_buffer (len, payload, memory_mode);
	MHD_add_response_header (response, "Content-Type", mime_type);
	ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
  	MHD_destroy_response (response);

	return ret;
}

static void free_resources(void)
{
	CachedResources* curNode = cachedresources;
	while (curNode != NULL) {
		CachedResources* nextNode = curNode->nextNode;
		free(curNode->location);
		free(curNode->rawdata);
		free(curNode);
		curNode = nextNode;
	}

	printf("Motd Server Exit!\n");
}


int main ()
{
	printf("Motd Server Start!\n");
	atexit(free_resources);

  	struct MHD_Daemon *daemon =
		MHD_start_daemon (MHD_USE_SELECT_INTERNALLY | MHD_USE_THREAD_PER_CONNECTION, PORT, NULL, NULL,
		&answer_to_connection, NULL, MHD_OPTION_END);

	if (NULL == daemon) {
		printf("[Error] Unable to start MOTD server deamon!\n");
		return 1;
	}

	(void) getchar ();

	MHD_stop_daemon (daemon);
	return 0;
}

int handle_svr_query(const char* addr, void** responce, size_t* len, int* memory_mode) {
	char buffer[512];
	struct L4D2REP_QUERYSVRINFO result;
	int ret = L4D2_QueryServerInfo(addr, &result, buffer, sizeof(buffer));

	if (ret == L4D2REP_OK) {
		*memory_mode = MHD_RESPMEM_MUST_FREE;
		char* str = (char*) malloc(32);
		snprintf(str, 32, "(%d/%d)", result.player_count, result.slots);
		*responce = str;
	} else {
		*memory_mode = MHD_RESPMEM_PERSISTENT;
		*responce = "(?/?)";
	}

	*len = strlen(*responce);
	printf("(svrquery = %s) <= %s\n", addr, (char*)*responce);

	return 1;
}
