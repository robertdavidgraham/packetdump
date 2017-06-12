#include "config.h"
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

enum {
    CONF_NUM,
    CONF_BOOL,
    CONF_NOTBOOL,
    CONF_STR,
};
enum {
    CONF_NOECHO = 1,
    CONF_COMMENT = 2,
};
struct ConfigurationOptions {
    const char *name;
    int type;
    size_t offset;
    int flags;
};

/***************************************************************************
 * Macro to grab structure member given the offsetof() value
 ***************************************************************************/
#define VAR(name) offsetof(PacketDump,name)
#define MEMBERAT(conf, n, t) (t*)&((char*)(conf))[n]

/***************************************************************************
 * The configured list of all possible configuration values
 ***************************************************************************/
static const struct ConfigurationOptions options[] = {
    {"filesize",    CONF_NUM,   VAR(rotate_size)},
    {"filetime",    CONF_NUM,   VAR(rotate_seconds)},
    {"maxfiles",    CONF_NUM,   VAR(rotate_filecount)},
    {"interface",   CONF_STR,   VAR(ifname)},
    {"writefile",   CONF_STR,   VAR(filename)},
    {"bpf",         CONF_STR,   VAR(bpf_rule)},
    {"bpf-file",    CONF_STR,   VAR(bpf_file)},
    {"compress",    CONF_BOOL,  VAR(is_compression)},
    {"gmt",         CONF_BOOL,  VAR(is_gmt)},
    
    
    {"monitor-mode",CONF_BOOL,  VAR(is_monitor_mode)},
    {"no-promiscuous-mode", CONF_NOTBOOL,VAR(is_promiscuous_mode)},
    {"relinquish-privileges", CONF_STR, VAR(drop_user)},
    
    {"help",        CONF_BOOL,  VAR(is_help), CONF_NOECHO},
    {"version",     CONF_BOOL,  VAR(is_version), CONF_NOECHO},
    {"list-interfaces",CONF_BOOL,VAR(is_iflist), CONF_NOECHO},
    {"echo",        CONF_BOOL,  VAR(is_echo), CONF_NOECHO},
    {0}
};

/***************************************************************************
 ***************************************************************************/
void
echo_configuration(FILE *fp, struct PacketDump *conf)
{
    size_t i;
    uint64_t *num;
    char *b;
    char **str;

    for (i=0; options[i].name; i++) {
        if (options[i].flags & CONF_NOECHO)
            continue;
        
        fprintf(fp, "%s = ", options[i].name);
        switch (options[i].type) {
            case CONF_NUM:
                num = MEMBERAT(conf, options[i].offset, uint64_t);
                fprintf(fp, "%llu\n", *num);
                break;
                
            case CONF_BOOL:
                b = MEMBERAT(conf, options[i].offset, char);
                fprintf(fp, "%s\n", (*b)?"true":"false");
                break;
            case CONF_NOTBOOL:
                b = MEMBERAT(conf, options[i].offset, char);
                fprintf(fp, "%s\n", (*b)?"false":"true");
                break;
            case CONF_STR:
                str = MEMBERAT(conf, options[i].offset, char *);
                fprintf(fp, "%s\n", (*str)?(*str):"");
                break;
            default:
                fprintf(fp, "<unimplemented option>\n");
                break;
        }
    }
}

/***************************************************************************
 * Parse the boolean value (true, false, t, f, 1, 0, etc.). If the value
 * string isn't a legal value, then this returns 0 and does not touch
 * the original value.
 * @return 1 if success, 0 is failure
 ***************************************************************************/
int
parse_boolean(const char *value, char *result)
{
    int is_match = 0;
    
    if (value == 0 || value[0] == '\0') {
        return 0;
    }
    
    is_match = !strcasecmp(value, "t")
    || !strcasecmp(value, "true")
    || !strcasecmp(value, "1")
    || !strcasecmp(value, "on");
    if (is_match) {
        *result = 1;
        return 1;
    }
    
    is_match = !strcasecmp(value, "f")
    || !strcasecmp(value, "false")
    || !strcasecmp(value, "0")
    || !strcasecmp(value, "off");
    if (is_match) {
        *result = 0;
        return 1;
    }
    
    /* parse failure */
    return 0;
}

/***************************************************************************
 * Whether the named option is of a "boolean" type, according to our list
 * of options. Note that this isn't parsing the value to see if it's true
 * for false, but parsing the name, and looking up in our list of 
 * possible options.
 ***************************************************************************/
static int
is_option_boolean(const char *name)
{
    size_t i;
    for (i=0; options[i].name; i++) {
        if (strcmp(options[i].name, name)==0) {
            if (options[i].type == CONF_BOOL || options[i].type == CONF_NOTBOOL)
                return 1;
            else
                return 0;
        }
    }
    return 0;
}


/***************************************************************************
 ***************************************************************************/
void
parse_option(const char *name, const char *value, struct PacketDump *conf)
{
    uint64_t *num;
    char *b;
    char **str;
    int is_valid;
    size_t i;
    
    /*
     * Find the template for the option
     */
    for (i=0; options[i].name; i++) {
        if (strcmp(options[i].name, name) == 0)
            break;
    }
    if (options[i].name == NULL) {
        fprintf(stderr, "%s: unknown option\n", name);
        return;
    }
    
    /*
     * parse the option according to the template
     */
    switch (options[i].type) {
        case CONF_NUM:
            num = MEMBERAT(conf, options[i].offset, uint64_t);
            *num = strtoull(value, 0, 0);
            break;
        
        case CONF_BOOL:
        case CONF_NOTBOOL:
            b = MEMBERAT(conf, options[i].offset, char);
            
            is_valid = parse_boolean(value, b);
            
            if (!is_valid) {
                fprintf(stderr, "%s: not a boolean value, expected 'true' or 'false'\n", name);
            } else if (options[i].type == CONF_NOTBOOL) {
                *b = !(*b);
            }
            break;
        case CONF_STR:
            str = MEMBERAT(conf, options[i].offset, char*);
            if (*str)
                free(*str);
            if (value == NULL || value[0] == '\0')
                *str = NULL;
            else
                *str = strdup(value);
            break;
            
        default:
            fprintf(stderr, "internal error: option type unknown\n");
            exit(1);
    }
}

/***************************************************************************
 ***************************************************************************/
static int
is_ending(const char *lhs, const char *rhs)
{
    size_t left_len = strlen(lhs);
    size_t right_len = strlen(rhs);
    
    if (left_len < right_len)
        return 0;
    
    return memcmp(lhs + left_len - right_len, rhs, right_len) == 0;
}


/***************************************************************************
 ***************************************************************************/
void
read_configuration(int argc, char **argv, struct PacketDump *conf)
{
    int i;
    
    for (i=1; i<argc; i++) {
        const char *value;
        
        if (argv[i][0] == '-' && argv[i][1] == '-') {
            char *name = malloc(strlen(argv[i]));
            /* We have an option of the format:
             * --bool
             * --bool true
             * --name value
             * --name=value */
            
            if (strchr(argv[i], '=')) {
                value = strchr(argv[i], '=');
                size_t len = value - (argv[i]+2);
                memcpy(name, argv[i]+2, len);
                name[len] = '\0';
                value = value + 1;
            } else {
                memcpy(name, argv[i]+2, strlen(argv[i]+2)+1);
                
                if (i+1 >= argc || argv[i+1][0] == '-') {
                    if (is_option_boolean(name))
                        value = "true";
                    else {
                        fprintf(stderr, "%s: missing value\n", name);
                        continue;
                    }
                } else
                    value = argv[++i];
            }
            parse_option(name, value, conf);
            free(name);
        } else if (argv[i][0] == '-') {
            const char *name;
            switch (argv[i][1]) {
                case 'C': name = "filesize"; break;
                case 'D': name = "list-interfaces"; break;
                case 'F': name = "bpf-file"; break;
                case 'G': name = "filetime"; break;
                case 'h': name = "help"; break;
                case '?': name = "help"; break;
                case 'i': name = "interface"; break;
                case 'I': name = "monitor-mode"; break;
                case 'p': name = "no-promiscuous-mode"; break;
                case 'r': name = "readfile"; break;
                case 'w': name = "writefile"; break;
                case 'W': name = "maxfiles"; break;
                case 'z': name = "compress"; break;
                case 'Z': name = "relinquish-privileges"; break;
                default:
                    fprintf(stderr, "%s: bad option\n", argv[i]);
                    continue;
            }
            if (argv[i][2] == '=') {
                value = argv[i]+3;
            } else if (argv[i][2]) {
                value = argv[i]+2;
            } else if (i+1 >= argc || argv[i+1][0] == '-') {
                if (is_option_boolean(name))
                    value = "true";
                else {
                    fprintf(stderr, "%s: missing value", name);
                    continue;
                }
            } else {
                value = argv[++i];
            }
            
            parse_option(name, value, conf);
        }
    }
    
    /*
     * if the file ends in the name of a compression algorithm, then
     * enable the compression flag.
     */
    if (conf->filename && is_ending(conf->filename, ".lz4"))
        conf->is_compression = 1;
}

/***************************************************************************
 ***************************************************************************/
void
configuration_help(void)
{
    printf(
           "usage: packetdump -i <ifname> -w <filename> [options]\n"
           "options:\n"
           " -C <filesize>\n"
           "   Maximum size of file before it rotates.\n"
           " -D\n"
           " --list-interfaces\n"
           "   Prints list of possible packet capture interfaces.\n"
           " -F <filename>\n"
           "   Read BPF filter rules from this file.\n"
           " -G <seconds>\n"
           "   Rotate file after this number of seconds.\n"
           " -i <ifname>\n"
           " --interface=<ifname>\n"
           "   Sniff on this network interface\n"
           " -I\n"
           " --monitor-mode\n"
           "   On WiFi interfaces, sets rfmon mode\n"
           " -p\n"
           " --no-promiscuous-mode\n"
           "   Do NOT put the adapter into promiscuous mode.\n"
           " -r <filename>\n"
           "   Read packets from a file.\n"
           " -w <filename>\n"
           "  Write packets to a file.\n"
           " -W <count>\n"
           "  Creates ring-buffer with this number of files.\n"
           " --version\n"
           "  Print version info.\n"
           " -z [compression type]\n"
           "  Enable compression. Not needed if file suffix indicates compression.\n"
           " -Z <user>\n"
           " --relinquish-privileges=user\n"
           "   Drops root privileges to those of this user\n"
           "\n");
}


