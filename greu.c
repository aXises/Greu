#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <netdb.h>
#include <errno.h>
#include <err.h>
#include <fcntl.h>

#include <stdio.h>
#include <inttypes.h>
#include <errno.h>
#include <string.h>

#include <event.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <sys/queue.h>

#include <net/if.h>
#include <net/if_tun.h>
#include <net/if_types.h>

#define PACKET_ETHERNET htons(0x6558)
#define PACKET_IPV4 htons(0x0800)
#define PACKET_IPV6 htons(0x86DD)
#define GRE_KP 0x2000  /* Key Present */

#define BUFFER_SIZE 1023

struct gre_header
{
	uint16_t gre_flags;
	uint16_t gre_proto;
} __packed __aligned(4);

enum exit_status {EXIT_NORMAL, EXIT_ERROR};

enum device_type{TYPE_TAP, TYPE_TUN};

struct device_config
{
	enum device_type type;
	char *dev_path;
	char *key;
};

struct prog_options
{
	sa_family_t af;
	int no_daemon;
	char *local_address;
	char *source_port;
	char *server;
	char *destin_port;
};

struct device
{
	TAILQ_ENTRY(device)
	entry;
	struct prog_options options;
	struct device_config config;
	struct event ev;
	int socket_fd;
};
TAILQ_HEAD(device_list, device);

__dead static void
usage(void)
{
		extern char *__progname;
		fprintf(stderr, "usage: %s [-46d] [-l address] [-p port]\n"
						"[-e /dev/tapX[@key]] [-i /dev/tunX[@key]]\n"
						"server [port]\n",
				__progname);
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
		while ((segment = strsep(&string, delim)) != NULL)
		{
			if (strlen(segment) != 0)
			{
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

		if (arr_size == 2)
		{
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
parse_args(struct device_list *devices, int argc, char *argv[])
{
		struct prog_options options;
		options.af = AF_UNSPEC;
		options.no_daemon = 0;
		options.local_address = NULL;
		options.source_port = NULL;
		int c;
		while ((c = getopt(argc, argv, "46dl:p:e:i:")) != -1)
		{
			switch (c)
			{
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
			{
				struct device *dev = setup_device(optarg, TYPE_TAP);
				TAILQ_INSERT_TAIL(devices, dev, entry);
				break;
			}
			case 'i':
			{
				struct device *dev = setup_device(optarg, TYPE_TUN);
				TAILQ_INSERT_TAIL(devices, dev, entry);
				break;
			}
			default:
				usage();
				/* NOTREACHED */
			}
		}
		if (optind > argc || argc - optind > 2 || argc - optind == 0)
		{
			usage();
		}
		if (argc - optind == 1)
		{
			options.server = argv[argc - 1];
			options.destin_port = "4754";
		}
		else if (argc - optind == 2)
		{
			options.server = argv[argc - 2];
			options.destin_port = argv[argc - 1];
		}
		if (options.source_port == NULL)
		{
			options.source_port = options.destin_port;
		}
		return options;
}

void
free_devices(struct device *dev, struct device_list devices)
{
		TAILQ_FOREACH(dev, &devices, entry)
		{
			free(dev->config.dev_path);
			free(dev->config.key);
		}
}

int
make_device_fd(struct device *dev)
{
		int fd = open(dev->config.dev_path, O_RDWR);
		if (fd < 0)
		{
			printf("Error opening %s\n", dev->config.dev_path);
			return fd;
		}

		int flags = 1;
		int error = ioctl(fd, FIONBIO, &flags);
		if (error)
		{
			printf("ioctl error: %i\n", error);
			return error;
		}

		return fd;
}

int
create_local_server(char *hostname, char *port)
{
		struct addrinfo hints, *res, *res0;
		int error;
		const char *cause;

		memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_INET;
		hints.ai_socktype = SOCK_DGRAM;

		error = getaddrinfo(hostname, port, &hints, &res0);
		if (error != 0)
		{
			errx(1, "host %s port %s: %s", hostname, port,
				gai_strerror(error));
		}

		int sock_fd;
		for (res = res0; res != NULL; res = res->ai_next)
		{
			sock_fd = socket(res->ai_family, res->ai_socktype | SOCK_NONBLOCK,
							res->ai_protocol);
			if (sock_fd == -1)
			{
				cause = strerror(errno);
				continue;
			}

			if (bind(sock_fd, res->ai_addr, res->ai_addrlen) == -1)
			{
				cause = strerror(errno);
				close(sock_fd);
				continue;
			}
			break;
		}
		if (sock_fd < 0)
		{
			err(1, "%s", cause);
		}
		freeaddrinfo(res0);
		return sock_fd;
}

int
connect_to_remote(char *remote_name, char *remote_port)
{
		struct addrinfo hints, *res, *res0;
		int error;
		const char *cause;

		memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_INET;
		hints.ai_socktype = SOCK_DGRAM;
		error = getaddrinfo(remote_name, remote_port, &hints, &res0);
		if (error != 0)
		{
			errx(1, "host %s port %s: %s", remote_name, remote_port,
				gai_strerror(error));
		}

		int server_fd;
		for (res = res0; res != NULL; res = res->ai_next)
		{
			server_fd = socket(res->ai_family, res->ai_socktype | SOCK_NONBLOCK,
							res->ai_protocol);
			if (server_fd == -1)
			{
				cause = strerror(errno);
				continue;
			}

			if (connect(server_fd, res->ai_addr, res->ai_addrlen) < 0)
			{
				cause = strerror(errno);
				close(server_fd);
				continue;
			}
			break;
		}
		if (server_fd < 0)
		{
			err(1, "%s", cause);
		}
		freeaddrinfo(res0);
		return server_fd;
}

/*
* Device ready, read the packets from interface. Encapsulate it and write it
* to our remote fd.
*/
void
interface_msg_received(int fd, short event, void *conn)
{
		struct device *dev = (struct device *)conn;
		struct gre_header header;
		ssize_t read_size;
		char *data, *packet;
		uint32_t *tun_af, net_key;
		int read_offset = 0;

		header.gre_flags = 0x0000;
		printf("device ready: %i with key %s\n", fd, dev->config.key);

		data = malloc(BUFFER_SIZE);
		read_size = read(fd, data, BUFFER_SIZE);

		if (read_size < 0)
		{
			err(1, "Error reading from socket: %s\n", strerror(errno));
		}

		printf("-------------------- Interface Output:\n");
		for (int i = 0; i < read_size; i++)
		{
			printf("%x|", data[i]);
		}
		printf("\n");

		if (dev->config.type == TYPE_TAP)
		{
			header.gre_proto = PACKET_ETHERNET;
		}
		if (dev->config.type == TYPE_TUN)
		{
			tun_af = malloc(sizeof(uint32_t));
			memcpy(tun_af, data, sizeof(uint32_t));
			read_offset += sizeof(uint32_t);
			if (ntohl(*tun_af) == AF_INET)
			{
				header.gre_proto = PACKET_IPV4;
			}
			else if (ntohl(*tun_af) == AF_INET6)
			{
				header.gre_proto = PACKET_IPV6;
			}
			else
			{
				err(1, "Unsupported socket.\n");
			}
		}

		/*
		* GRE key present.
		*/
		if (dev->config.key != NULL) {
			header.gre_flags = header.gre_flags | GRE_KP;
			net_key = htons(strtoul(dev->config.key, NULL, 32));
			packet = malloc(sizeof(struct gre_header) + sizeof(uint32_t)
				+ (sizeof(char) * (read_size - read_offset)));
		}
		else
		{
			packet = malloc(sizeof(struct gre_header) +
				(sizeof(char) * (read_size - read_offset)));
		}

		/*
		* Append header.
		*/
		memcpy(packet, &header, sizeof(struct gre_header));

		/*
		* Append data and/or key.
		*/
		if (dev->config.key != NULL) {
			memcpy(&packet[sizeof(struct gre_header)], &net_key, sizeof(uint32_t));
			memcpy(&packet[sizeof(struct gre_header) + sizeof(uint32_t)], &data[read_offset], read_size - read_offset);
		}
		else {
			memcpy(&packet[sizeof(struct gre_header)], &data[read_offset], read_size - read_offset);
		}

		if (dev->config.key != NULL) {
			printf("-------------------- GRE Packet with key\n");
			for (int i = 0; i < sizeof(struct gre_header) + sizeof(uint32_t) + read_size; i++)
			{
				printf("%x|", packet[i]);
			}
			printf("\n");
		} else {
			printf("-------------------- GRE Packet no key\n");
			for (int i = 0; i < sizeof(struct gre_header) + read_size; i++)
			{
				printf("%x|", packet[i]);
			}
			printf("\n");
		}

		write(dev->socket_fd, packet, sizeof(struct gre_header) + read_size);
		// free(data);
}

int
main(int argc, char *argv[])
{
		struct device_list devices = TAILQ_HEAD_INITIALIZER(devices);
		struct prog_options options;
		struct device *dev;
		struct event *socket_conn_event;
		int sock_fd;

		options = parse_args(&devices, argc, argv);
		printf("greu - local_address: %s, source_port %s, server: %s, destination_port: %s\n", options.local_address, options.source_port, options.server, options.destin_port);

		sock_fd = create_socket_fd(options.af, options.local_address, options.source_port,
			options.server, options.destin_port);

		printf("Socket fd: %i\n", sock_fd);

		event_init();

		socket_conn_event = malloc(sizeof(struct event));
		event_set(socket_conn_event, sock_fd, EV_READ | EV_PERSIST,
				socket_msg_received, socket_conn_event);
		event_add(socket_conn_event, NULL);

		TAILQ_FOREACH(dev, &devices, entry)
		{
			dev->options = options;
			dev->socket_fd = sock_fd;
			int device_fd = make_device_fd(dev);
			printf("Interface %s created on fd: %i\n", dev->config.dev_path, device_fd);
			event_set(&dev->ev, device_fd, EV_READ | EV_PERSIST,
					interface_msg_received, dev);
			event_add(&dev->ev, NULL);
		}

		event_dispatch();

		free_devices(dev, devices);
		return EXIT_NORMAL;
}
