#!/bin/bash

# If save is provided, (like `./test.sh save`) the test runner will automatically save the results
# into a .txt file and make sure the tests runs. This helps to make sure I have updated tests when needed.

SKC_EXEC="./bin/skc"
FAIL=0
SUCCESS=0
TOTAL=0
RED="\033[31m"
GREEN="\033[32m"
RESET="\033[0m"
PURPLE="\033[35m"
BOLD="\033[1m"

ERRORS=""

echo -e $RED
echo -e '┏━  The Stańczyk Programming Language  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃                                                                      ┃
┃            ¿«fº"└└-.`└└*∞▄_              ╓▄∞╙╙└└└╙╙*▄▄               ┃
┃         J^. ,▄▄▄▄▄▄_      └▀████▄ç    JA▀            └▀v             ┃
┃       ,┘ ▄████████████▄¿     ▀██████▄▀└      ╓▄██████▄¿ "▄_          ┃
┃      ,─╓██▀└└└╙▀█████████      ▀████╘      ▄████████████_`██▄        ┃
┃     ;"▄█└      ,██████████-     ▐█▀      ▄███████▀▀J█████▄▐▀██▄      ┃
┃     ▌█▀      _▄█▀▀█████████      █      ▄██████▌▄▀╙     ▀█▐▄,▀██▄    ┃
┃    ▐▄▀     A└-▀▌  █████████      ║     J███████▀         ▐▌▌╙█µ▀█▄   ┃
┃  A╙└▀█∩   [    █  █████████      ▌     ███████H          J██ç ▀▄╙█_  ┃
┃ █    ▐▌    ▀▄▄▀  J█████████      H    ████████          █    █  ▀▄▌  ┃
┃  ▀▄▄█▀.          █████████▌           ████████          █ç__▄▀ ╓▀└╙%_┃
┃                 ▐█████████      ▐    J████████▌          .└╙   █¿  ,▌┃
┃                 █████████▀╙╙█▌└▐█╙└██▀▀████████                 ╙▀▀▀ ┃
┃                ▐██▀┘Å▀▄A └▓█╓▐█▄▄██▄J▀@└▐▄Å▌▀██▌                     ┃
┃                █▄▌▄█M╨╙└└-           .└└▀**▀█▄,▌                     ┃
┃                ²▀█▄▄L_                  _J▄▄▄█▀└                     ┃
┃                     └╙▀▀▀▀▀MMMR████▀▀▀▀▀▀▀└                          ┃
┃                                                                      ┃
┃                                                                      ┃
┃ ███████╗████████╗ █████╗ ███╗   ██╗ ██████╗███████╗██╗   ██╗██╗  ██╗ ┃
┃ ██╔════╝╚══██╔══╝██╔══██╗████╗  ██║██╔════╝╚══███╔╝╚██╗ ██╔╝██║ ██╔╝ ┃
┃ ███████╗   ██║   ███████║██╔██╗ ██║██║       ███╔╝  ╚████╔╝ █████╔╝  ┃
┃ ╚════██║   ██║   ██╔══██║██║╚██╗██║██║      ███╔╝    ╚██╔╝  ██╔═██╗  ┃
┃ ███████║   ██║   ██║  ██║██║ ╚████║╚██████╗███████╗   ██║   ██║  ██╗ ┃
┃ ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝ ┃
┃                                                                      ┃'

echo -ne $RESET

for FILE in tests/*.sk; do
    if [ -f "$FILE" ]; then
        TOTAL=$(($TOTAL + 1))
        TEST_SRC="${FILE%.*}"
        TEST_NAME="${TEST_SRC##*/}"

        if [ "$1" == "save" ]; then
            ${SKC_EXEC} build ${TEST_SRC}.sk -clean -silent
            ./output > ${TEST_SRC}.txt
        fi

        ${SKC_EXEC} build ${TEST_SRC}.sk -clean -silent
        ./output > result.txt

        RESULT=$(diff ${TEST_SRC}.txt result.txt)
        echo -en $RED'┃'
        printf "${RESET}${BOLD} ¤ %-56s${RESET}" $TEST_NAME

        if [ -z "$RESULT" ]; then
            echo -ne "${GREEN}✔ success${RESET}"
            SUCCESS=$(($SUCCESS + 1))
        else
            echo -ne "${RED}✗ fail${RESET}   "
            FAIL=$(($FAIL + 1))
            if [ "$1" == "show" ]; then
                ERRORS+="${BOLD}  ¤ ${TEST_NAME}.sk${RESET}\n\t- ${RESULT}\n"
            fi
        fi

        echo -e $RED'  ┃'
        rm result.txt
        rm output
    fi
done

RCOLOR=""
if [[ "$FAIL" -gt 0 ]]; then
    RCOLOR="$RED"
else
    RCOLOR="$GREEN"
fi
echo -e $RED'┃                                                                      ┃
┃                                                                      ┃'
printf "${RED}┃${RESET}                                   ${RCOLOR}${BOLD}TOTAL %2d :: Success %2d | Fails %2d${RESET}" $TOTAL $SUCCESS $FAIL
echo -e $RED'  ┃'
echo -e $RED'┃                                                                      ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  The Stańczyk Programming Language  ━┛'

if [ "$1" == "show" ]; then
    echo -e "${RESET}"
    echo -e "Errors:"
    echo -e "${ERRORS}"
fi

exit $FAIL
