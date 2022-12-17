#ifndef MYTELNET
#define MYTELNET

#include "trameinfo.h"

#define TERMINAL_TYPE 0x18
#define NAWS 0x1F
#define TS 0x05
#define TTYPE 0x18
#define ECHO 0x01
#define SUPPRESS_GO_AHEAD 0x03
#define STATUS 0x05
#define TIMING_MARK 0x06
#define TERMINAL_SPEED 0x20
#define REMOTE_FLOW_CONTROL 0x21
#define LINEMODE 0x22
#define X_DISPLAY_LOCATION 0x23
#define ENVIRONMENT_VARIABLE 0x24
#define AUTHENTICATION 0x25
#define ENCRYPTION 0x26
#define NEW_ENVIRONMENT 0x27
#define TN3270E 0x28
#define XAUTH 0x29
#define CHARSET 0x2A
#define RSP 0x2B
#define COM_PORT_CONTROL 0x2C
#define SUPPRESS_LOCAL_ECHO 0x2D
#define START_TLS 0x2E
#define KERMIT 0x2F
#define SEND_URL 0x30
#define FORWARD_X 0x2D
#define PRAGMA_LOGON 0x3A
#define SSPI_LOGON 0x3B
#define PRAGMA_HEARTBEAT 0x3C
#define EXOPL 0xFF

#define SE 0xF0
#define NOP 0xF1
#define DM 0xF2
#define BRK 0xF3
#define IP 0xF4
#define AO 0xF5
#define AYT 0xF6
#define EC 0xF7
#define EL 0xF8
#define GA 0xF9
#define SB 0xFA
#define WILL 0xFB
#define WONT 0xFC
#define DO 0xFD
#define DONT 0xFE
#define IAC 0xFF



/**
 * @brief Decode TELNET trame since packet
 */
int DecodeTELNET(const u_char *packet, struct trameinfo *trameinfo);

#endif