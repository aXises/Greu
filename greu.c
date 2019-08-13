#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <netdb.h>
#include <errno.h>
#include <err.h>

#include <event.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <sys/queue.h>

enum exit_status {EXIT_NORMAL, EXIT_ERROR} exit_status;

struct prog_options
{
	sa_family_t af;
	int no_daemon;
	char *local_address;
	char *source_port;
	char *server;
	char *destin_port;
} ;

__dead static void
usage(void)
{
		extern char *__progname;
		fprintf(stderr, "usage: %s [-46d] [-l address] [-p port]\n"
						"[-e /dev/tapX[@key]] [-i /dev/tunX[@key]]\n"
						"server [port]\n", __progname);
		exit(EXIT_ERROR);
}

/**
* Split an string in to an array of strings by an character.
* @param string - The string to split.
* @param delim - The character to split by.
* @return char - An array of split strings.
*/
char **
split(char *string, char *delim, int *size)
{
		char *segment = NULL;
		char **split_string = malloc(sizeof(char *));
		int counter = 0;
		while ((segment = strsep(&string, delim)) != NULL) {
			if (strlen(segment) != 0) {
				split_string = realloc(split_string,
					sizeof(char *) * (counter + 1));
				split_string[counter] = segment;
				counter++;
			}
		}
		*size = counter;
		return split_string;
}

struct device *
setup_device(char *dev_str, enum device_type type)
{
		struct device_config config;
		config.type = type;
		config.dev_path = NULL;
		config.key = NULL;

		int arr_size;
		char **split_string = split(dev_str, "@", &arr_size);

		config.dev_path = malloc(sizeof(split_string[0]));
		strcpy(config.dev_path, split_string[0]);

		if (arr_size == 2) {
			char *key = split_string[1];
			config.key = malloc(strlen(key));
			strcpy(config.key, key);
		}

		free(split_string);
		struct device *dev = malloc(sizeof(struct device));
		dev->config = config;
		return dev;
}

struct prog_options
parse_args(int argc, char *argv[])
{
		struct prog_options options;
		options.af = AF_UNSPEC;
		options.no_daemon = 0;
		options.local_address = NULL;
		options.source_port = NULL;
		int c;
		while ((c = getopt(argc, argv, "46dl:p:e:i:")) != -1) {
			switch (c) {
			case '4':
				options.af = AF_INET;
				break;
			case '6':
				options.af = AF_INET6;
				break;
			case 'd':
				options.no_daemon = 1;
			case 'l':
				options.local_address =
					(strcmp(optarg, "*") == 0) ? NULL : optarg;
				break;
			case 'p':
				options.source_port = optarg;
				break;
			case 'e':
				break;
			case 'i':
				break;
			default:
				usage();
				/* NOTREACHED */
			}
		}
		if (optind > argc || argc - optind > 2 || argc - optind == 0) {
			usage();
		}
		if (argc - optind == 1) {
			options.server = argv[argc - 1];
			options.destin_port = "4754";
		} else if (argc - optind == 2) {
			options.server = argv[argc - 2];
			options.destin_port = argv[argc - 1];
		}
		if (options.source_port == NULL) {
			options.source_port = options.destin_port;
		}
		return options;
}

int
main(int argc, char *argv[])
{
		struct prog_options options = parse_args(argc, argv);
		printf("address: %s, source_port %s, server: %s, destination_port: %s\n", options.local_address, options.source_port, options.server, options.destin_port);
		return EXIT_NORMAL;
}
