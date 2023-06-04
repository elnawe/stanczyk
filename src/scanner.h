/* The Stańczyk Programming Language
 *
 *            ¿«fº"└└-.`└└*∞▄_              ╓▄∞╙╙└└└╙╙*▄▄
 *         J^. ,▄▄▄▄▄▄_      └▀████▄ç    JA▀            └▀v
 *       ,┘ ▄████████████▄¿     ▀██████▄▀└      ╓▄██████▄¿ "▄_
 *      ,─╓██▀└└└╙▀█████████      ▀████╘      ▄████████████_`██▄
 *     ;"▄█└      ,██████████-     ▐█▀      ▄███████▀▀J█████▄▐▀██▄
 *     ▌█▀      _▄█▀▀█████████      █      ▄██████▌▄▀╙     ▀█▐▄,▀██▄
 *    ▐▄▀     A└-▀▌  █████████      ║     J███████▀         ▐▌▌╙█µ▀█▄
 *  A╙└▀█∩   [    █  █████████      ▌     ███████H          J██ç ▀▄╙█_
 * █    ▐▌    ▀▄▄▀  J█████████      H    ████████          █    █  ▀▄▌
 *  ▀▄▄█▀.          █████████▌           ████████          █ç__▄▀ ╓▀└ ╙%_
 *                 ▐█████████      ▐    J████████▌          .└╙   █¿   ,▌
 *                 █████████▀╙╙█▌└▐█╙└██▀▀████████                 ╙▀▀▀▀
 *                ▐██▀┘Å▀▄A └▓█╓▐█▄▄██▄J▀@└▐▄Å▌▀██▌
 *                █▄▌▄█M╨╙└└-           .└└▀**▀█▄,▌
 *                ²▀█▄▄L_                  _J▄▄▄█▀└
 *                     └╙▀▀▀▀▀MMMR████▀▀▀▀▀▀▀└
 *
 *
 * ███████╗████████╗ █████╗ ███╗   ██╗ ██████╗███████╗██╗   ██╗██╗  ██╗
 * ██╔════╝╚══██╔══╝██╔══██╗████╗  ██║██╔════╝╚══███╔╝╚██╗ ██╔╝██║ ██╔╝
 * ███████╗   ██║   ███████║██╔██╗ ██║██║       ███╔╝  ╚████╔╝ █████╔╝
 * ╚════██║   ██║   ██╔══██║██║╚██╗██║██║      ███╔╝    ╚██╔╝  ██╔═██╗
 * ███████║   ██║   ██║  ██║██║ ╚████║╚██████╗███████╗   ██║   ██║  ██╗
 * ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝
 */
#ifndef STANCZYK_SCANNER_H
#define STANCZYK_SCANNER_H

#include "stanczyk.h"

typedef enum {
    TOKEN_INT,
    TOKEN_STR,
    TOKEN_FLOAT,
    TOKEN_HEX,

    TOKEN_DATATYPE_INT,
    TOKEN_DATATYPE_STR,
    TOKEN_DATATYPE_BOOL,
    TOKEN_DATATYPE_PTR,
    TOKEN_DATATYPE_FLOAT,
    TOKEN_DATATYPE_HEX,

    TOKEN_LEFT_PAREN,
    TOKEN_RIGHT_PAREN,

    TOKEN_RIGHT_ARROW,

    TOKEN_COLON,
    TOKEN_AND,
    TOKEN_DEC,
    TOKEN_DO,
    TOKEN_DOT,
    TOKEN_DROP,
    TOKEN_TAKE,
    TOKEN_DUP,
    TOKEN_ELSE,
    TOKEN_EQUAL,
    TOKEN_GREATER,
    TOKEN_GREATER_EQUAL,
    TOKEN_IF,
    TOKEN_INC,
    TOKEN_LESS,
    TOKEN_LESS_EQUAL,
    TOKEN_LOAD8,
    TOKEN_LOOP,
    TOKEN_NOT_EQUAL,
    TOKEN_OR,
    TOKEN_OVER,
    TOKEN_PRINT,
    TOKEN_SAVE8,
    TOKEN_SWAP,
    TOKEN_WORD,

    TOKEN_FUNCTION,
    TOKEN_C_FUNCTION,
    TOKEN_CONST,
    TOKEN_MACRO,
    TOKEN_STATIC,
    TOKEN_SET,
    TOKEN_END,

    TOKEN_HASH_INCLUDE,
    TOKEN_HASH_CLIB,

    TOKEN___SYS_ADD,
    TOKEN___SYS_SUB,
    TOKEN___SYS_MUL,
    TOKEN___SYS_DIVMOD,

    TOKEN___SYS_CALL0,
    TOKEN___SYS_CALL1,
    TOKEN___SYS_CALL2,
    TOKEN___SYS_CALL3,
    TOKEN___SYS_CALL4,
    TOKEN___SYS_CALL5,
    TOKEN___SYS_CALL6,

    TOKEN_ERROR,
    TOKEN_EOF
} TokenType;

typedef struct {
    TokenType type;
    const char *filename;
    const char *start;
    u32 length;
    u32 line;
    u32 column;
} Token;

void init_scanner(const char *,const char *);
Token scan_token();

#endif
