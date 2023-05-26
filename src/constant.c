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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "memory.h"
#include "constant.h"
#include "object.h"

void init_constants_array(ConstantArray *array) {
    array->capacity = 0;
    array->count = 0;
    array->values = NULL;
}

void write_constants_array(ConstantArray* array, Value value) {
    if (array->capacity < array->count + 1) {
        int prev_capacity = array->capacity;
        array->capacity = GROW_CAPACITY(prev_capacity);
        array->values = GROW_ARRAY(Value, array->values, prev_capacity, array->capacity);
    }

    array->values[array->count] = value;
    array->count++;
}

void free_constants_array(ConstantArray* array) {
    FREE_ARRAY(int, array->values, array->capacity);
    init_constants_array(array);
}

static char *escape(const char *src) {
    int i, j;
    char *pw;

    for (i = j = 0; src[i] != '\0'; i++) {
        if (src[i] == '\n' || src[i] == '\t' ||
            src[i] == '\\' || src[i] == '\"') {
            j++;
        }
    }
    pw = malloc(i + j + 1);

    for (i = j = 0; src[i] != '\0'; i++) {
        switch (src[i]) {
        case '\n': pw[i+j] = '\\'; pw[i+j+1] = 'n'; j++; break;
        case '\t': pw[i+j] = '\\'; pw[i+j+1] = 't'; j++; break;
        case '\\': pw[i+j] = '\\'; pw[i+j+1] = '\\'; j++; break;
        case '\"': pw[i+j] = '\\'; pw[i+j+1] = '\"'; j++; break;
        default:   pw[i+j] = src[i]; break;
        }
    }
    pw[i+j] = '\0';
    return pw;
}

void print_constant(Value value) {
    switch(value.type) {
        case VALUE_NUMBER: printf("%d", AS_NUMBER(value));  break;
        case VALUE_OBJECT: printf("%s", escape(AS_CSTRING(value))); break;
    }

}
