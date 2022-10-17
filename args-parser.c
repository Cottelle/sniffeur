
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/errno.h>

#include "args-parser.h"

void printhelp(void)
{

    printf("Usage : analyseur [OPTION]");
    printf("\n\n  -i <interface>     Listen on this interface (default \?\?)");
    printf("\n  -o <file>            Listen on the file (offline)");
    printf("\n  -f <filter>          Use filter");
    printf("\n  -c <number>          Listen number packet after stop (-1 or default to ifinit lopp)");
    printf("\n  -v <level>           Print info with diffrent verbose level (1 -low | 2 - meduim | 3 -lot");
    printf("\n  -u                   Don't print with color\n\n");
    return;
}

void cleanOptions(struct options_t *options)
{
    options = options;
    return;
}

void initOptions(struct options_t *options)
{
    options->action = ACTION_UNKNOWN;
    options->interface = NULL;
    options->off_file = NULL;
    options->filter = NULL;
    options->colors = 1;
    options->verbose = 1;
    options->count = -1;
}

// void checkOptionsValidity(struct options_t *options)
// {
//     if (options->action != ACTION_DEBUG)
//     {
//         if (options->inputFilename == NULL)
//         {
//             fprintf(stderr, "Need an input file for each options\n");
//             exit(6);
//         }
//         if (options->action == ACTION_PLUSCOURTCHEMIN && options->Auteur1 == NULL)
//         {
//             fprintf(stderr, "this action requires two names of authors c'mon man\n");
//             exit(1);
//         }
//         if (options->action == ACTION_INFOAUTEUR && options->Auteur1 == NULL)
//         {
//             fprintf(stderr, "InfoAuteur action requires at least the name of one author, c'mon man.\n");
//             exit(2);
//         }
//         if (options->action == ACTION_VOISINDISTN)
//         {
//             if (options->Auteur1 == NULL)
//             {
//                 fprintf(stderr, "this action requires at least the name of one author c'mon man\n");
//                 exit(3);
//             }
//             if (options->distanceN == -1)
//             {
//                 fprintf(stderr, "you need to give the distance maximum between your author and the others ones\n");
//                 exit(4);
//             }
//         }
//         if (options->action == ACTION_LISTMOT)
//         {
//             if (options->Mot == NULL)
//             {
//                 // readMessageFromStdin(&options->Mot, &options->messageLength);
//                 fprintf(stderr, "listmot action requires a word, c'mon man\n");
//                 exit(5);
//             }
//         }
//         if (options->action == ACTION_PARSEANDSTORE)
//         {
//             if (options->inputFilename == NULL || options->outputFilename == NULL)
//             {
//                 fprintf(stderr, "pour parser (-b) il faut indiquer un fichier source (celui à parser) et un fichier destination (pour stocker en biniare) \n");
//                 exit(6);
//             }
//         }
//     }
// }

void parseArgs(int argc, char **argv, struct options_t *options)
{

    initOptions(options);

    int c;
    while ((c = getopt(argc, argv, "i:o:f:v:c:uh")) != -1)
    {
        switch (c)
        {
        case 'h':
            printhelp();
            exit(7);
        case 'i':
            options->interface = optarg;
            break;
        case 'o':
            options->off_file = optarg;
            break;
        case 'f':
            options->filter = optarg;
            break;
        case 'u':
            options->colors = 0;
            break;
        case 'c':
            options->count = (unsigned int)atoi(optarg);
            break;
        case 'v':
            options->verbose = atoi(optarg);
            break;

        case '?':
            fprintf(stderr, "Unknown option, try again\n");
            if (optopt == 'i' || optopt == 'o' || optopt == 'f' || optopt == 'v' || optopt == 'c')
                fprintf(stderr, "Option -%c requires an argument.\n", optopt);
            else if (isprint(optopt))
                fprintf(stderr, "Unknown option `-%c'.\n", optopt);
            else
                fprintf(stderr,
                        "Unknown option character `\\x%x'.\n",
                        optopt);
            abort();
        default:
            abort();
        }
    }

    // checkOptionsValidity(options);
}