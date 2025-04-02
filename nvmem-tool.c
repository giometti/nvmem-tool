/*
 * nvmem-tool.c - Simple NVMEM tool
 *
 * (c) 2024-2025 Rodolfo Giometti <giometti@enneenne.com>
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <getopt.h>
#include <string.h>
#include <dirent.h>
#include <libgen.h>
#include <inttypes.h>
#include "misc.h"
#include "nvmem-tool.h"

#ifndef ETH_ALEN
#define ETH_ALEN	6		/* Octets in one ethernet addr	 */
#endif

/*
 * Global variables & definitions
 */

#define SYSFS_NVMEM_DIR		"bus/nvmem/devices"
#define SYSFS_DEVICETREE_BASE	"firmware/devicetree/base"

static char *nvmem_type_str[__NVMEM_TYPE_END] = {
	[NVMEM_TYPE_UNKNOWN]		= "Unknown",
	[NVMEM_TYPE_EEPROM]		= "EEPROM",
	[NVMEM_TYPE_OTP]		= "OTP",
	[NVMEM_TYPE_BATTERY_BACKED]	= "Battery backed",
	[NVMEM_TYPE_FRAM]		= "FRAM",
};

enum nvmem_fmt_e {
	NVMEM_FMT_U8,
	NVMEM_FMT_U16,
	NVMEM_FMT_U32,
	NVMEM_FMT_U64,
	NVMEM_FMT_MAC,
	NVMEM_FMT_STRING,
	NVMEM_FMT_RAW,
	__NVMEM_FMT_END
};

static char *nvmem_fmt_str[__NVMEM_FMT_END] = {
	[NVMEM_FMT_U8]		= "u8",
	[NVMEM_FMT_U16]		= "u16",
	[NVMEM_FMT_U32]		= "u32",
	[NVMEM_FMT_U64]		= "u64",
	[NVMEM_FMT_MAC]		= "mac",
	[NVMEM_FMT_STRING]	= "string",
	[NVMEM_FMT_RAW]		= "raw",
};

static struct nvmem_dev_t *nvmem_dev;
static size_t nvmem_dev_num;

int debug_level;
static bool nvmem_mode;
static char *nvmem_name;
static bool porcelain_mode;
static bool dump_mode;
static bool show_all;
static enum nvmem_fmt_e force_fmt = __NVMEM_FMT_END;
#define is_forced_fmt(v)	(v != __NVMEM_FMT_END)
#define is_raw_fmt(v)		(v == NVMEM_FMT_RAW)
static char *sysfs = "/sys";			/* the default location       */
static bool base10;

/*
 * Misc functions
 */

#define pprintf(fmt, args...)						\
	do {								\
		if (!porcelain_mode)					\
			printf(fmt , ## args);				\
	} while (0)

static void dump_buf(const uint8_t buf[], size_t len)
{
	size_t i;

	for (i = 0; i < len; i++) {
		if (i % 16 == 0)
			printf("%08zx: ", i);
		printf("%02x ", buf[i]);
		if ((i + 1) % 16 == 0)
			printf("\n");
	}
	if (i % 16 != 0)
		printf("\n");
}

static enum nvmem_fmt_e parse_fmt(const char *name)
{
	enum nvmem_fmt_e i;

	for (i = 0; i < __NVMEM_FMT_END; i++)
		if (strcmp(nvmem_fmt_str[i], name) == 0)
			return i;

	fatal("unknow format %s", name);
}

static void print_buf_u(const size_t bits, const uint8_t buf[], size_t len)
{
	size_t i;
	size_t n = len / (bits / 8);
	const uint8_t *pu8 = buf;
	const uint16_t *pu16 = (const uint16_t *) buf;
	const uint32_t *pu32 = (const uint32_t *) buf;
	const uint64_t *pu64 = (const uint64_t *) buf;

	if (n == 0)
		fatal("too few data for format");
	if (n * (bits / 8) != len)
		fatal("invalid data alignment for format");
	for (i = 0; i < n; i++) {
		switch (bits) {
		case 8:
			if (base10)
				printf("%02" PRId8 " ", pu8[i]);
			else
				printf("%02" PRIx8 " ", pu8[i]);
			break;

		case 16:
			if (base10)
				printf("%04" PRId16 " ", pu16[i]);
			else
				printf("%04" PRIx16 " ", pu16[i]);
			break;

		case 32:
			if (base10)
				printf("%08" PRId32 " ", pu32[i]);
			else
				printf("%08" PRIx32 " ", pu32[i]);
			break;

		case 64:
			if (base10)
				printf("%016" PRId64 " ", pu64[i]);
			else
				printf("%016" PRIx64 " ", pu64[i]);
			break;

		default:
			BUG();
		}
	}
}
#define print_buf_u8(buf, len)		print_buf_u(8, buf, len)
#define print_buf_u16(buf, len)		print_buf_u(16, buf, len)
#define print_buf_u32(buf, len)		print_buf_u(32, buf, len)
#define print_buf_u64(buf, len)		print_buf_u(64, buf, len)

static void print_mac(const uint8_t buf[ETH_ALEN])
{
	printf("%02x:%02x:%02x:%02x:%02x:%02x",
		buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]);
}

static void print_string(const uint8_t *buf, size_t len)
{
	size_t i;
	for (i = 0; i < len; i++)
		if (buf[i] == 0)
			break;
	if (i == len)
		fatal("cannot print not null terminated strings!");
	printf("%s", buf);
}

static void print_raw(const uint8_t *buf, size_t len)
{
	fwrite(buf, len, 1, stdout);
}

static void print_buf(const uint8_t buf[], size_t len, enum nvmem_fmt_e fmt)
{
	switch (fmt) {
	case NVMEM_FMT_U8:
		print_buf_u8(buf, len);
		break;

	case NVMEM_FMT_U16:
		print_buf_u16(buf, len);
		break;

	case NVMEM_FMT_U32:
		print_buf_u32(buf, len);
		break;

	case NVMEM_FMT_U64:
		print_buf_u64(buf, len);
		break;

	case NVMEM_FMT_MAC:
		if (len != 6)
			fatal("invalid MAC address size for cell");
		print_mac(buf);
		break;

	case NVMEM_FMT_STRING:
		print_string(buf, len);
		break;

	case NVMEM_FMT_RAW:
		print_raw(buf, len);
		break;

	default:
		BUG();
	}
}

static enum nvmem_fmt_e autodetect_fmt(struct nvmem_dev_t *dev,
						struct nvmem_ofnode_t *node)
{
	char *firstname;

	if (is_forced_fmt(force_fmt))
		return force_fmt;

	firstname = node->cell;
	if (strlen(node->cell) == 0)
		firstname = node->name;

	/* Check for MAC addresses */
	if ((strcmp("mac", firstname) == 0 ||
	     strcmp("mac-address", firstname) == 0) &&
	    node->len == 6)
		return NVMEM_FMT_MAC;

	/* Check for simple data */
	switch (node->len) {
	case 2:
		return NVMEM_FMT_U16;
	case 4:
		return NVMEM_FMT_U32;
	case 8:
		return NVMEM_FMT_U64;
	}

	return NVMEM_FMT_U8;
}

static size_t print_label(struct nvmem_dev_t *dev, struct nvmem_ofnode_t *node)
{
	char *surname, *firstname;

	surname = node->sym;
	firstname = node->cell;
	if (strlen(node->sym) == 0 || strlen(node->cell) == 0) {
		surname = dev->ofname;
		firstname = node->name;
	}
	return printf("%s:%s", surname, firstname);
}

static void print_cell(struct nvmem_dev_t *dev, struct nvmem_ofnode_t *node,
				uint8_t buf[], size_t size)
{
	enum nvmem_fmt_e fmt;

	fmt = autodetect_fmt(dev, node);
	print_buf(buf, size, fmt);
}

static size_t scan_buf_u(const size_t bits, const char *data,
				uint8_t buf[], size_t len)
{
	size_t i;
	uint64_t v;
	int pos, n;
	uint8_t *pu8 = buf;
	uint16_t *pu16 = (uint16_t *) buf;
	uint32_t *pu32 = (uint32_t *) buf;
	uint64_t *pu64 = (uint64_t *) buf;
	int ret;

	pos = 0;
	for (i = 0; i < len && pos < strlen(data); i++, pos += n) {
		if (base10)
			ret = sscanf(data + pos, "%" PRId64 "%n", &v, &n);
		else
			ret = sscanf(data + pos, "%" PRIx64 "%n", &v, &n);
		if (ret != 1)
			fatal("cannot parse at position %zu", i + 1);
		if (ret == EOF)
			break;
		if (bits < 64 && v > ((UINT64_C(1) << bits) - 1))
			fatal("invalid value at position %zu", i + 1);

		switch (bits) {
		case 8:
			pu8[i] = v;
			break;

		case 16:
			pu16[i] = v;
			break;

		case 32:
			pu32[i] = v;
			break;

		case 64:
			pu64[i] = v;
			break;

		default:
			BUG();
		}
	}

	return i * (bits / 8);
}
#define scan_buf_u8(data, buf, len)	scan_buf_u(8, data, buf, len)
#define scan_buf_u16(data, buf, len)	scan_buf_u(16, data, buf, len)
#define scan_buf_u32(data, buf, len)	scan_buf_u(32, data, buf, len)
#define scan_buf_u64(data, buf, len)	scan_buf_u(64, data, buf, len)

static size_t scan_mac(const char *data, uint8_t buf[], size_t len)
{
	unsigned int v[6];
	size_t i;
	int ret;

	if (len < 6)
		fatal("too short cell to hold a mac address");

	ret = sscanf(data, "%x:%x:%x:%x:%x:%x",
			&v[0], &v[1], &v[2], &v[3], &v[4], &v[5]);
        if (ret != 6)
                fatal("too short or invalid mac address");

	for (i = 0; i < 6; i++)
		if (v[i] > 0xff)
			fatal("invalid mac address");
		else
			buf[i] = v[i];

	return 6;
}

static size_t scan_string(const char *data, uint8_t buf[], size_t len)
{
        size_t i;

        for (i = 0; i < len; i++)
                if ((buf[i] = data[i]) == 0)
                        break;
        if (i == len)
                fatal("cannot parse (or store) not null terminated strings!");
	buf[++i] = '\0';

	return i;
}

static size_t scan_raw(uint8_t buf[], size_t len)
{
	size_t i = fread(buf, len, 1, stdin);
	if (i < 1)
		fatal("cannot read raw data");

	return len;
}

static size_t scan_buf(const char *data, uint8_t buf[], size_t len,
						enum nvmem_fmt_e fmt)
{
	size_t n;

	switch (fmt) {
	case NVMEM_FMT_U8:
		n = scan_buf_u8(data, buf, len);
		break;

	case NVMEM_FMT_U16:
		n = scan_buf_u16(data, buf, len);
		break;

	case NVMEM_FMT_U32:
		n = scan_buf_u32(data, buf, len);
		break;

	case NVMEM_FMT_U64:
		n = scan_buf_u64(data, buf, len);
		break;

	case NVMEM_FMT_MAC:
		n = scan_mac(data, buf, len);
		break;

	case NVMEM_FMT_STRING:
		n = scan_string(data, buf, len);
		break;

	case NVMEM_FMT_RAW:
		if (strcmp(data, "-"))
			fatal("must specify \"-\" as data argument when "
				"--format=raw");
		n = scan_raw(buf, len);
		break;

	default:
		BUG();
	}
	BUG_ON(n > len);

	return n;
}

static size_t scan_cell(struct nvmem_dev_t *dev, struct nvmem_ofnode_t *node,
			const char *data, uint8_t **buf)
{
	enum nvmem_fmt_e fmt;

	*buf = malloc(node->len);
	if (!*buf)
		fatal("cannot allocate memory");

	fmt = autodetect_fmt(dev, node);
	return scan_buf(data, *buf, node->len, fmt);
}

static void parse_cell_name(char *name, char **sym, char **cell)
{
	int ret;

	ret = sscanf(name, "%m[^:]:%m[^:]", sym, cell);
	if (ret == 0)
		fatal("cannot parse cell name");
	if (ret == 1) {
		*cell = *sym;
		*sym = NULL;
	}
	return;
}

static void find_cell_by_name(char *name, struct nvmem_dev_t **dev,
				struct nvmem_ofnode_t **node)
{
	char *surname = NULL, *firstname = NULL;
	size_t c, n;
	bool found = false;

	dbg("name=%s", name);
	parse_cell_name(name, &surname, &firstname);
	dbg("surname=%s firstname=%s", surname, firstname);
	BUG_ON(strlen(firstname) == 0);

	for (n = 0; n < nvmem_dev_num; n++) {
		*dev = &nvmem_dev[n];

		for (c = 0; c < (*dev)->ofnode_num; c++) {
			*node = &(*dev)->ofnode[c];
	
			if (strcmp(firstname, (*node)->cell) == 0) {
				found = true;
				if (surname &&
				    strcmp(surname, (*node)->sym) != 0)
					continue;
			} else if (strcmp(firstname, (*node)->name) == 0) {
                                found = true;
                                if (surname &&
                                    strcmp(surname, (*dev)->ofname) != 0)
                                        continue;
			} else
				continue;

			if (found)
				goto free_str;
		}
	}
	fatal("no cell named as %s", name);

free_str:
	free(surname);
	free(firstname);
}

/*
 * SYSFS functions
 */

static int sysfs_read_file(const char *path, size_t off, size_t len,
				uint8_t buf[])
{
	FILE *f;
	int ret;

	f = fopen(path, "r");
	if (!f)
		return -1;
	ret = fseek(f, off, SEEK_SET);
	if (ret < 0)
		fatal("cannot seek file %s", path);
	ret = fread(buf, 1, len, f);
	fclose(f);
	if (ret < 0)
		fatal("cannot read file %s", path);

	return ret;
}

static int sysfs_write_file(const char *path, size_t off, size_t len,
				uint8_t buf[])
{
	FILE *f;
	int ret;

	f = fopen(path, "r+");
	if (!f)
		return -1;
	ret = fseek(f, off, SEEK_SET);
	if (ret < 0)
		fatal("cannot seek file %s", path);
	ret = fwrite(buf, 1, len, f);
	fclose(f);
	if (ret < 0)
		fatal("cannot write file %s", path);

	return ret;
}

static void sysfs_read_str(const char *path, char *str, size_t len)
{
	int ret;

	ret = sysfs_read_file(path, 0, len, (uint8_t *) str);
	if (ret < 0)
		return;

	if (ret == 0) {
		str[0] = '\0';
		return;
	}
	if (str[ret - 1] == '\n')
		str[ret - 1] = '\0';
}

int sysfs_raw_read_u32(const char *path, uint32_t val[], size_t num)
{
	FILE *f;
	int ret;

	memset(val, 0, sizeof(uint32_t) * num);

	f = fopen(path, "r");
	if (!f)
		return -1;
	ret = fread(val, 1, sizeof(uint32_t) * num, f);
	fclose(f);
	if (ret < 0)
		fatal("cannot read file %s", path);

	return ret;
}

uint32_t sysfs_read_phandle(const char *path)
{
	uint32_t v;
	int ret;

	ret = sysfs_raw_read_u32(path, &v, 1);
	if (ret < 0)
		return 0xffffffff;

	return be32toh(v);
}

static void sysfs_read_compatible(const char *path, char *str, size_t len)
{
	char *property;
	int ret;

        ret = asprintf(&property, "%s/compatible", path);
	if (ret < 0)
		fatal("cannot allocate memory");

	sysfs_read_str(property, str, len);
	free(property);
}

/*
 * NVMEM parsing functions
 */

static size_t nvmem_read_ofnode(struct nvmem_dev_t *dev,
				struct nvmem_ofnode_t *node,
				uint8_t **buf, size_t *buf_size)
{
	char *path;
	int ret;

        ret = asprintf(&path, "%s/%s/%s/nvmem",
				sysfs, SYSFS_NVMEM_DIR, dev->name);
	if (ret < 0)
		fatal("cannot allocate memory");

	if (*buf_size < node->len) {
		*buf = realloc(*buf, node->len);
		if (!*buf)
			fatal("cannot allocate memory");
		*buf_size = node->len;
	}

	sysfs_read_file(path, node->off, node->len, *buf);
	free(path);

	return node->len;
}

static size_t nvmem_write_ofnode(struct nvmem_dev_t *dev,
				struct nvmem_ofnode_t *node,
				uint8_t *buf, size_t buf_size)
{
	char *path;
	int ret;

	if (buf_size > node->len)
		fatal("cannot write %zu bytes in cell", buf_size);

        ret = asprintf(&path, "%s/%s/%s/nvmem",
				sysfs, SYSFS_NVMEM_DIR, dev->name);
	if (ret < 0)
		fatal("cannot allocate memory");

	sysfs_write_file(path, node->off, buf_size, buf);
	free(path);
	return node->len;
}

static void nvmem_dump_data(struct nvmem_dev_t *dev)
{
	char *path;
	uint8_t buf[PAGE_SIZE];
	size_t n;
	int ret;

        ret = asprintf(&path, "%s/%s/%s/nvmem",
				sysfs, SYSFS_NVMEM_DIR, dev->name);
	if (ret < 0)
		fatal("cannot allocate memory");

	n = 0;
	while ((ret = sysfs_read_file(path, n, sizeof(buf), buf)) > 0) {
		dump_buf(buf, ret);
		n += ret;
	}

	free(path);
}

static struct nvmem_dev_t *find_nvmem_dev_by_name(const char *name)
{
	char *firstname;
	size_t n;

	for (n = 0; n < nvmem_dev_num; n++) {
		firstname = nvmem_dev[n].ofname;
		if (strlen(firstname) == 0)
			firstname = nvmem_dev[n].name;
		if (strcmp(firstname, name) == 0)
			return &nvmem_dev[n];
	}
	fatal("no NVMEM device named as %s", name);
}

static enum nvmem_type_e nvmem_get_type(const char *name)
{
	char *path, type[64];
	enum nvmem_type_e t;
	int ret;

        ret = asprintf(&path, "%s/%s/%s/type",
				sysfs, SYSFS_NVMEM_DIR, name);
	if (ret < 0)
		fatal("cannot allocate memory");

	sysfs_read_str(path, type, sizeof(type));

	for (t = 0; t < __NVMEM_TYPE_END; t++)
		if (strcmp(nvmem_type_str[t], type) == 0)
			break;
	if (t == __NVMEM_TYPE_END)
		fatal("unknown type '%s' for NVMEM device %s", type, name);

	free(path);

	return t;
}

static int nvmem_get_ofname(const char *name, char ofname[NVMEM_STR_MAXLEN])
{
	char *path, link[256];
	ssize_t n;
	int ret;

        ret = asprintf(&path, "%s/%s/%s/of_node",
				sysfs, SYSFS_NVMEM_DIR, name);
	if (ret < 0)
		fatal("cannot allocate memory");

	n = readlink(path, link, sizeof(link));
	if (n < 0)
		return n;
	if (n == sizeof(link))
		fatal("cannot read link properly!");
	link[n] = '\0';

	strcpy(ofname, basename(link));

	return 0;
}

static void nvmem_get_symbol(const char *name, char sym[NVMEM_STR_MAXLEN])
{
	char *path;
	int ret;

        ret = asprintf(&path, "%s/%s/__symbols__/%s",
				sysfs, SYSFS_DEVICETREE_BASE, name);
	if (ret < 0)
		fatal("cannot allocate memory");

	sysfs_read_str(path, sym, NVMEM_STR_MAXLEN);

	free(path);
}

static void nvmem_get_cell_names(const char *name, char *cell)
{
	char *path;
	int ret;

        ret = asprintf(&path, "%s/%s/%s/nvmem-cell-names",
				sysfs, SYSFS_DEVICETREE_BASE, name);
	if (ret < 0)
		fatal("cannot allocate memory");
	sysfs_read_str(path, cell, NVMEM_STR_MAXLEN);

	free(path);
}

static uint32_t nvmem_get_cells(const char *name)
{
	char *path;
	uint32_t cells;
	int ret;

        ret = asprintf(&path, "%s/%s/%s/nvmem-cells",
				sysfs, SYSFS_DEVICETREE_BASE, name);
	if (ret < 0)
		fatal("cannot allocate memory");

	cells = sysfs_read_phandle(path);

	free(path);

	return cells;
}

/*
 * Parsing functions
 */

void parse_symbols_for_nvmem(uint32_t phandle, char *sym, char *cell)
{
	char path[PATH_MAX];
	char link[NVMEM_STR_MAXLEN];
	DIR *d;
	struct dirent *e;
	uint32_t cells;
	int ret;

        ret = snprintf(path, PATH_MAX, "%s/%s/__symbols__",
				sysfs, SYSFS_DEVICETREE_BASE);
        BUG_ON(ret >= PATH_MAX);

	d = opendir(path);
	if (!d) {
		dbg("no directory %s", path);
		return;
	}

	while ((e = readdir(d))) {
		if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
			continue;
		if (e->d_type != DT_REG)
			continue;

		nvmem_get_symbol(e->d_name, link);
		cells = nvmem_get_cells(link);
		if (phandle != cells)
			continue;

		strcpy(sym, e->d_name);
		nvmem_get_cell_names(link, cell);
	}

	closedir(d);
}

struct nvmem_ofnode_t *add_new_nvmem_cell(struct nvmem_dev_t *dev)
{
	int n = dev->ofnode_num++;
	struct nvmem_ofnode_t *node;

	dev->ofnode = realloc(dev->ofnode,
				sizeof(*dev->ofnode) * dev->ofnode_num);
	if (!dev->ofnode)
		fatal("cannot store NVMEM of_node(s) info");
	node = &dev->ofnode[n];
	memset(node, 0, sizeof(*node));

	return node;
}

static void detect_nvmem_layout(struct nvmem_dev_t *dev)
{
	struct stat buf;
        char path[PATH_MAX], compatible[NVMEM_STR_MAXLEN];
	int ret;

        ret = snprintf(path, PATH_MAX, "%s/%s/%s/of_node/nvmem-layout",
                                sysfs, SYSFS_NVMEM_DIR, dev->name);
        BUG_ON(ret >= PATH_MAX);
        ret = stat(path, &buf);
        if (ret < 0) {
		/* Legacy layout? */
		ret = snprintf(path, PATH_MAX, "%s/%s/%s/of_node",
				sysfs, SYSFS_NVMEM_DIR, dev->name);
		BUG_ON(ret >= PATH_MAX);

		strcpy(compatible, "legacy-layout");
		dbg("legacy layout detected!");
	} else
		sysfs_read_compatible(path, compatible, NVMEM_STR_MAXLEN);
	dbg("compatible=%s", compatible);

	if (strncmp(compatible, "fixed-layout", sizeof(compatible)) == 0 ||
	    strncmp(compatible, "legacy-layout", sizeof(compatible)) == 0) {
		ret = parse_fixed_layout(dev, path);
		if (ret < 0)
			dbg("no cells for device %s", dev->name);
	} else {
		warn("unsupported layout for NVMEM device %s!", dev->name);
	}
}

static void add_new_nvmem_dev(const char *name)
{
	int n = nvmem_dev_num++;
	int ret;

	nvmem_dev = realloc(nvmem_dev, sizeof(*nvmem_dev) * nvmem_dev_num);
	if (!nvmem_dev)
		fatal("cannot store NVMEM devices info");
	nvmem_dev[n].ofnode = NULL;
	nvmem_dev[n].ofnode_num = 0;

	strncpy(nvmem_dev[n].name, name, NVMEM_STR_MAXLEN);
	nvmem_dev[n].type = nvmem_get_type(nvmem_dev[n].name);
	ret = nvmem_get_ofname(nvmem_dev[n].name, nvmem_dev[n].ofname);
	if (ret < 0)
		strcpy(nvmem_dev[n].ofname, nvmem_dev[n].name);
	detect_nvmem_layout(&nvmem_dev[n]);

	dbg("nvmem%d name=%s type=%d ofnodes=%zu", n,
		nvmem_dev[n].name, nvmem_dev[n].type, nvmem_dev[n].ofnode_num);
}

static void parse_nvmem_devs(void)
{
	char path[PATH_MAX];
	DIR *d;
	struct dirent *e;
	int ret;

        ret = snprintf(path, PATH_MAX, "%s/%s", sysfs, SYSFS_NVMEM_DIR);
        BUG_ON(ret >= PATH_MAX);

	d = opendir(path);
	if (!d)
		fatal("cannot open directory %s/%s", sysfs, SYSFS_NVMEM_DIR);

	while ((e = readdir(d))) {
		if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
			continue;
		dbg("name=%s", e->d_name);
		BUG_ON(strlen(e->d_name) >= NVMEM_STR_MAXLEN);

		add_new_nvmem_dev(e->d_name);
	}

	closedir(d);
}

/*
 * Commands
 */

static void cmd_list_nvmems(void)
{
	size_t n;

	pprintf("name                 type             #node(s)\n"
			"-----------------------------------------------------------------------------\n");
	for (n = 0; n < nvmem_dev_num; n++) {
		if (!show_all && nvmem_dev[n].type == NVMEM_TYPE_UNKNOWN)
			continue;

		printf("%-20s %-16s %-3zu\n", nvmem_dev[n].ofname,
			nvmem_type_str[nvmem_dev[n].type],
			nvmem_dev[n].ofnode_num);
	}
}

static void cmd_show_nvmem(char *name)
{
	struct nvmem_dev_t *dev;
	struct nvmem_ofnode_t *node;
	size_t n;

	dbg("name=%s", name);
	dev = find_nvmem_dev_by_name(name);

	if (dump_mode) {
		nvmem_dump_data(dev);
		return ;
	}

	if (dev->ofnode_num == 0) {
		pprintf("no of_node(s)!\n");
		return;
	}

	pprintf("name                   offset/length   cell\n"
			"-----------------------------------------------------------------------------\n");
	for (n = 0; n < dev->ofnode_num; n++) {
		node = &dev->ofnode[n];
		printf("%-20s %#8x/%#-8x %s:%s\n", node->name,
			node->off, node->len,
			node->sym, node->cell);
	}
}

static void cmd_list_cells(void)
{
	struct nvmem_dev_t *dev;
	struct nvmem_ofnode_t *node;
	size_t c, n, len;
	uint8_t *buf = NULL;
	size_t buf_size = 0;
	size_t nchar;

	for (n = 0; n < nvmem_dev_num; n++) {
		dev = &nvmem_dev[n];

		for (c = 0; c < dev->ofnode_num; c++) {
			node = &dev->ofnode[c];
	
			nchar = print_label(dev, node);
			if (dump_mode) {
				/* Do a pretty print by adding spaces */
				nchar = nchar >= 40 ? 0 : 40 - nchar;
				while (nchar-- > 0)
					printf(" ");

				len = nvmem_read_ofnode(dev, node,
							&buf, &buf_size);
				print_cell(dev, node, buf, len);
			}
			printf("\n");
		}
	}

	free(buf);
}

static void cmd_read_cell(char *name)
{
	struct nvmem_dev_t *dev;
	struct nvmem_ofnode_t *node;
	size_t len;
	uint8_t *buf = NULL;
	size_t buf_size = 0;

	find_cell_by_name(name, &dev, &node);

	len = nvmem_read_ofnode(dev, node, &buf, &buf_size);
	print_cell(dev, node, buf, len);
	if (!is_raw_fmt(force_fmt))
		printf("\n");

	free(buf);
}

static void cmd_write_cell(char *name, char *data)
{
	struct nvmem_dev_t *dev;
	struct nvmem_ofnode_t *node;
	size_t len;
	uint8_t *buf;

	find_cell_by_name(name, &dev, &node);

	len = scan_cell(dev, node, data, &buf);
	dbg_dump(buf, len, "write[%zu]:", len);
	nvmem_write_ofnode(dev, node, buf, len);

	free(buf);
}

/*
 * Usage
 */

static void usage(void)
{
        fprintf(stderr, "usage:\n");
        fprintf(stderr, "\t%s <options>\t\t\t\t\t: list detected NVMEM cells\n", NAME);
        fprintf(stderr, "\t%s <options> --nvmem\t\t\t\t: list detected NVMEM devices\n", NAME);
        fprintf(stderr, "\t%s <options> --nvmem=<dev>\t\t\t: list cells within the NVMEM device <dev>\n", NAME);
        fprintf(stderr, "\t%s <options> <cell>\t\t\t\t: read data in the first cell named <cell>\n", NAME);
        fprintf(stderr, "\t%s <options> --nvmem=<dev> <cell>\t\t, or\n", NAME);
        fprintf(stderr, "\t%s <options> <dev>:<cell>\t\t\t: read data in the cell named <cell> within the NVMEM device <dev>\n", NAME);
        fprintf(stderr, "\t%s <options> --nvmem=<dev> <cell> <data>\t, or\n", NAME);
        fprintf(stderr, "\t%s <options> <dev>:<cell> <data>\t\t: write <data> in the cell named <cell> within the NVMEM device <dev>\n", NAME);
        fprintf(stderr, "  <options> can be one or more of:\n"
                "    -h                    : print this helping message\n"
                "    -d                    : enable debugging messages\n"
                "    --base10              : print numbers in dec instead of hex\n"
                "    --porcelain           : enable the porcelain output\n"
                "    --dump                : enable dump mode\n"
                "    --show-all            : show also \"Unknown\" devices\n"
                "    --format=<fmt>        : show data as \"u8\", \"u16\", \"u32\", \"u64\", \"mac\", \"string\", or \"raw\"\n"
                "    --sysfs-dir           : set sysfs mount directory to <dir> (defaults to %s)\n", sysfs);
}

/*
 * Main
 */

int main(int argc, char *argv[])
{
        int opt;
        int long_index = 0;
        static struct option options[] = {
                { "help",	no_argument,		NULL, 'h' },
                { "debug",	no_argument,		NULL, 'd' },
                { "version",	no_argument,		NULL, 'v' },
                { "nvmem",	optional_argument,	NULL, 1000 },
                { "porcelain",	no_argument,		NULL, 1001 },
                { "dump",	no_argument,		NULL, 1002 },
                { "show-all",	no_argument,		NULL, 1003 },
                { "format",	required_argument,	NULL, 1004 },
                { "sysfs-dir",	required_argument,	NULL, 1005 },
                { "base10",	no_argument,		NULL, 1006 },
                { 0, 0, 0, 0 }
        };

        while ((opt = getopt_long(argc, argv, "dhv", options,
                            &long_index)) >= 0) {
                switch (opt) {
                case 'h':
                        usage();
                        exit(EXIT_SUCCESS);

                case 'd':
                        incr_debug(1);
                        break;

                case 'v':
                        printf("%s ver. %s\n", NAME, __VERSION);
                        break;

		case 1000:
			nvmem_mode = true;
			nvmem_name = optarg;
			break;

		case 1001:
			porcelain_mode = true;
			break;

		case 1002:
			dump_mode = true;
			break;

		case 1003:
			show_all = true;
			break;

		case 1004:
			force_fmt = parse_fmt(optarg);
			break;

		case 1005:
			sysfs = optarg;
			break;

		case 1006:
			base10 = true;
			break;

                default:
                        fatal("wrong option! Use -h for help");
                }
        }

	/* Try to detect all NVMEM devices */
	parse_nvmem_devs();

	switch (argc - optind) {
	case 0:
		if (!nvmem_mode)
			cmd_list_cells();
		else {
			if (nvmem_name)
				cmd_show_nvmem(nvmem_name);
			else
				cmd_list_nvmems();
		}

		break;

	case 1:
		if (!nvmem_mode)
			cmd_read_cell(argv[optind]);
		else {
			if (nvmem_name) {
				char *tmp;
				int ret = asprintf(&tmp, "%s:%s",
					nvmem_name, argv[optind]);
				if (ret < 0)
					fatal("cannot allocate memory");
				cmd_read_cell(tmp);
				free(tmp);
			} else
				fatal("must specify a NVMEM device name for "
					"--nvmem!");
		}

		break;

	case 2:
		if (!nvmem_mode)
			cmd_write_cell(argv[optind], argv[optind + 1]);
                else {
                        if (nvmem_name) {
                                char *tmp;
                                int ret = asprintf(&tmp, "%s:%s",
                                        nvmem_name, argv[optind]);
                                if (ret < 0)
                                        fatal("cannot allocate memory");
                                cmd_write_cell(tmp, argv[optind + 1]);
                                free(tmp);
                        } else
                                fatal("must specify a NVMEM device name for "
                                        "--nvmem!");
                }

		break;

	default:
		fatal("too much arguments!");
	}

	return 0;
}
