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
#define GRE_KP htons(0x2000)  /* Key Present */

#define BUFFER_SIZE 1023

struct gre_header
{
	uint16_t gre_flags;
	uint16_t gre_proto;
} __packed __aligned(4);

enum exit_status { EXIT_NORMAL, EXIT_ERROR };

enum device_type { TYPE_TAP, TYPE_TUN };

struct device_config
{
	enum device_type type;
	char *dev_path;
	char *key;
};

struct prog_options
{
	sa_family_t af;
	int         no_daemon;
	char        *local_address;
	char        *source_port;
	char        *server;
	char        *destin_port;
};

struct device
{
	TAILQ_ENTRY(device) entry;
	struct prog_options options;
	struct device_config config;
	struct event ev;
	int    socket_fd;
	int    device_fd;
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
	struct device *dev;
	int arr_size;
	char **split_string;
	char *key;
	config.type = type;
	config.dev_path = NULL;
	config.key = NULL;

	split_string = split(dev_str, "@", &arr_size);

	config.dev_path = malloc(sizeof(split_string[0]));
	strcpy(config.dev_path, split_string[0]);

	if (arr_size == 2)
	{
		key = split_string[1];
		config.key = malloc(strlen(key));
		strcpy(config.key, key);
	}

	free(split_string);
	dev = malloc(sizeof(struct device));
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
			break;
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
	int fd, flags, error;
	fd = open(dev->config.dev_path, O_RDWR);
	if (fd < 0)
	{
		err(1, "Error opening: %s, %s\n", dev->config.dev_path,
			strerror(errno));
		return fd;
	}

	flags = 1;
	error = ioctl(fd, FIONBIO, &flags);
	if (error)
	{
		err(1, "ioctol error: %s, %s\n", dev->config.dev_path,
			strerror(errno));
		return error;
	}

	return fd;
}

struct addrinfo *
generate_addrinfo(const char *name, const char *port, sa_family_t af)
{
		struct addrinfo hints;
		struct addrinfo *res;
		int error;
		
		memset(&hints, 0, sizeof(hints));
		hints.ai_family = af;
		hints.ai_socktype = SOCK_DGRAM;
		
		error = getaddrinfo(name, port, &hints, &res);
		
		if (error) {
			errx(1, "%s", gai_strerror(error));
		}
		
		return res;
}

int
create_socket_fd(sa_family_t af, char *hostname, char *port,
	char *remote_name, char *remote_port)
{
	struct addrinfo *src_addrinfo, *remote_addrinfo, *res;
	int sock_fd;
	const char *cause;

	src_addrinfo = generate_addrinfo(hostname, port, af);

	for (res = src_addrinfo; res != NULL; res = res->ai_next)
	{
		sock_fd = socket(res->ai_family,
			res->ai_socktype | SOCK_NONBLOCK, res->ai_protocol);
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

	remote_addrinfo = generate_addrinfo(remote_name, remote_port, af);
	for (res = remote_addrinfo; res != NULL; res = res->ai_next)
	{
		if (connect(sock_fd, res->ai_addr, res->ai_addrlen) < 0)
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

	freeaddrinfo(src_addrinfo);
	freeaddrinfo(remote_addrinfo);
	return sock_fd;
}

void
write_to_interface(struct gre_header header, struct device *dev,
	enum device_type type, uint32_t key, char *packet, ssize_t read_size)
{
	if (dev->config.type == type)
	{
		if (dev->config.key == NULL)
		{
			if (key == -1)
			{
				write(dev->device_fd,
					&packet[sizeof(struct gre_header)],
					read_size - sizeof(struct gre_header));
			}
		}
		else
		{
			if (ntohl(key) == strtoul(dev->config.key, NULL, 10))
			{
				write(dev->device_fd,
					&packet[sizeof(struct gre_header)
						+ sizeof(uint32_t)],
					read_size - sizeof(struct gre_header)
						- sizeof(uint32_t));
			}
		}
	}
}

/*
* Data received from remote fd, decapsulate it and write to our interface.
*/
void
socket_msg_received(int fd, short event, void *conn)
{
	struct device_list *devices = (struct device_list *) conn;
	struct device *dev = NULL;
	struct gre_header header;
	enum device_type packet_type;
	uint32_t key = -1;
	ssize_t read_size;
	char packet[BUFFER_SIZE];

	read_size = read(fd, packet, BUFFER_SIZE);

	if (read_size < 0)
	{
		err(1, "Error reading from %s: %s\n", dev->config.dev_path,
			strerror(errno));
	}

	// printf("-------------------- Socket Output:\n");
	// for (int i = 0; i < read_size; i++)
	// {
	// 	printf("%x|", packet[i]);
	// }
	// printf("\n");

	memcpy(&header, packet, sizeof(struct gre_header));

	// printf("flags %x\n", ntohs(header.gre_flags));
	// printf("proto %x\n", ntohs(header.gre_proto));

	if (header.gre_flags == GRE_KP)
	{
		memcpy(&key, &packet[sizeof(struct gre_header)],
			sizeof(uint32_t));
	}
	if (header.gre_proto == PACKET_ETHERNET)
	{
		packet_type = TYPE_TAP;
	}
	else
	{
		packet_type = TYPE_TUN;
	}

	TAILQ_FOREACH(dev, devices, entry)
	{
		write_to_interface(header, dev, packet_type, key, packet,
			read_size);
	}
}

void
write_to_server_socket(struct gre_header header, int fd, uint32_t key,
	enum device_type type, char *data, ssize_t read_size)
{
	int packet_size;
	char *packet;

	/*
	* Append header.
	*/
	packet = malloc(sizeof(struct gre_header));
	memcpy(packet, &header, sizeof(struct gre_header));

	packet_size = 0;
	if (key != -1)
	{
		packet = realloc(packet, sizeof(struct gre_header)
			+ sizeof(uint32_t) + read_size);
		memcpy(&packet[sizeof(struct gre_header)],
			&key, sizeof(uint32_t));
		packet_size += sizeof(struct gre_header)
					+ sizeof(uint32_t) + read_size;
		if (type == TYPE_TAP)
		{
			memcpy(&packet[sizeof(struct gre_header)
				+ sizeof(uint32_t)], &data, read_size);
		}
		else
		{
			memcpy(&packet[sizeof(struct gre_header)
				+ sizeof(uint32_t)], &data[sizeof(uint32_t)],
				read_size - sizeof(uint32_t));
			packet_size -= sizeof(uint32_t);
		}
	}
	else
	{ 
		packet = realloc(packet, sizeof(struct gre_header) + read_size);
		packet_size += sizeof(struct gre_header) + read_size;
		if (type == TYPE_TAP)
		{
			memcpy(&packet[sizeof(struct gre_header)],
				&data, read_size);
		}
		else
		{
			memcpy(&packet[sizeof(struct gre_header)],
				&data[sizeof(uint32_t)],
				read_size - sizeof(uint32_t));
			packet_size -= sizeof(uint32_t);
		}
	}

	// printf("-------------------- GRE Packet\n");
	// for (int i = 0; i < packet_size; i++)
	// {
	// 	printf("%x|", packet[i]);
	// }
	// printf("\n");

	write(fd, packet, packet_size);
	free(packet);
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
	uint32_t *tun_af, net_key;
	ssize_t read_size;
	char data[BUFFER_SIZE];

	header.gre_flags = 0x0000;
	// printf("device ready: %i with key %s\n", fd, dev->config.key);

	read_size = read(fd, data, BUFFER_SIZE);

	if (read_size < 0)
	{
		err(1, "Error reading from socket: %s\n", strerror(errno));
	}

	// printf("-------------------- Interface Output:\n");
	// for (int i = 0; i < read_size; i++)
	// {
	// 	// printf("|"BYTE_TO_BINARY_PATTERN, BYTE_TO_BINARY(data[i]));
	// 	printf("%x|", data[i]);
	// }
	// printf("\n");

	if (dev->config.type == TYPE_TAP)
	{
		header.gre_proto = PACKET_ETHERNET;
	}
	if (dev->config.type == TYPE_TUN)
	{
		tun_af = malloc(sizeof(uint32_t));
		memcpy(tun_af, data, sizeof(uint32_t));
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
		free(tun_af);
	}

	/*
	* GRE key present.
	*/
	net_key = -1;
	if (dev->config.key != NULL)
	{
		header.gre_flags = header.gre_flags | GRE_KP;
		net_key = htonl(strtoul(dev->config.key, NULL, 10));
	}

	write_to_server_socket(header, dev->socket_fd, net_key,
		dev->config.type, data, read_size);
}

int
main(int argc, char *argv[])
{
	struct device_list devices = TAILQ_HEAD_INITIALIZER(devices);
	struct event *socket_conn_event;
	struct prog_options options;
	struct device *dev;
	int sock_fd;

	options = parse_args(&devices, argc, argv);

	sock_fd = create_socket_fd(options.af, options.local_address,
		options.source_port, options.server, options.destin_port);

	if (!options.no_daemon)
	{
		daemon(0, 0);
	}

	event_init();

	TAILQ_FOREACH(dev, &devices, entry)
	{
		dev->options = options;
		dev->socket_fd = sock_fd;
		dev->device_fd = make_device_fd(dev);
		event_set(&dev->ev, dev->device_fd, EV_READ | EV_PERSIST,
				interface_msg_received, dev);
		event_add(&dev->ev, NULL);
	}

	socket_conn_event = malloc(sizeof(struct event));
	event_set(socket_conn_event, sock_fd, EV_READ | EV_PERSIST,
			socket_msg_received, &devices);
	event_add(socket_conn_event, NULL);

	event_dispatch();

	free_devices(dev, devices);
	return EXIT_NORMAL;
}
