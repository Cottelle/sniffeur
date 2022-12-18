#ifndef ARGS_PARSER_H
#define ARGS_PARSER_H
#include <stdio.h>
#include <inttypes.h>

typedef enum action_t {
    ACTION_UNKNOWN,
    ACTION_INTERFACE,
    ACTION_OUTUP_FILE,
    ACTION_FILTER,
    ACTION_COLORS,
    ACTION_VERBOSE,
} action_t;

/**
 * @brief Options that can be sent in the command line
 * 
 */
struct options_t {
    action_t action;
    char *interface;
    char *off_file;
    char *filter;
    char colors;
    char verbose;
    unsigned int count;
};


void parseArgs(int argc, char **argv, struct options_t *options);

#endif