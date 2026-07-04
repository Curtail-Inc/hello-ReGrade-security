#!/usr/bin/env bash
# ABOUTME: Renders styled "terminal + Claude Code + ReGrade MCP" scenes for the demo video.
# ABOUTME: Each function prints one beat; VHS records it into a clip. All numbers are real.
set -uo pipefail

DIM=$'\e[38;5;244m'; BOLD=$'\e[1m'; RST=$'\e[0m'
CYAN=$'\e[38;5;117m'; GRN=$'\e[38;5;114m'; YEL=$'\e[38;5;222m'; RED=$'\e[38;5;210m'
MAG=$'\e[38;5;183m'; ORANGE=$'\e[38;5;215m'; BLUE=$'\e[38;5;111m'

# "type" a command at a shell prompt, char by char
cmd() {
  printf '%s ' "${GRN}\$${RST}"
  local s="$1" i
  for ((i=0; i<${#s}; i++)); do printf '%s' "${s:$i:1}"; sleep 0.018; done
  printf '\n'; sleep 0.5
}
out()    { printf '%s\n' "$1"; sleep "${2:-0.35}"; }
user()   { printf '%s\n' "${DIM}› ${1}${RST}"; sleep 0.8; }
claude() { printf '%s %s\n' "${MAG}●${RST}" "$1"; sleep "${2:-0.7}"; }
tool()   { printf '%s %s\n' "${GRN}⏺${RST}" "${DIM}${1}${RST}"; sleep 0.6; }
hr()     { printf '%s\n' "${DIM}────────────────────────────────────────────────────${RST}"; }

# ask(): the customer types a plain-English message into the Claude Code prompt box.
ask() {
  local text="$1" W=66 i shown pad
  local CUR="${CYAN}▊${RST}"
  printf '\e[?25l'
  printf '  %s╭%s╮%s\n' "$DIM" "$(printf '─%.0s' $(seq 1 $W))" "$RST"
  for ((i=1; i<=${#text}; i++)); do
    shown="${text:0:i}"
    pad=$(( W - 4 - ${#shown} )); (( pad < 0 )) && pad=0
    printf '\r  %s│%s %s❯%s %s%s%*s%s│%s' \
      "$DIM" "$RST" "$CYAN" "$RST" "$shown" "$CUR" "$pad" "" "$DIM" "$RST"
    sleep 0.034
  done
  printf '\n'
  printf '  %s╰%s╯%s\n' "$DIM" "$(printf '─%.0s' $(seq 1 $W))" "$RST"
  printf '\e[?25h'
  sleep 0.9
}

title() {
  echo; echo; echo
  out "   ${CYAN}${BOLD}hello-ReGrade-security${RST}" 0.7
  out "   ${DIM}find the vulnerability your tests were never written to catch${RST}" 1.0
  echo
  out "   ${DIM}record  ${BLUE}→${DIM}  replay the app against itself  ${BLUE}→${DIM}  a leaked secret appears${RST}" 2.4
}

beat_problem() {
  out "${DIM}# a test only checks what you thought to assert${RST}" 1.0
  echo
  out "  ${GRN}✓${RST} login works      ${GRN}✓${RST} user renamed      ${GRN}✓${RST} all tests pass" 1.6
  echo
  out "${DIM}  …but no test ever asks:${RST}" 0.9
  out "  ${RED}✗${RST} did this response just leak a ${BOLD}password hash${RST}?" 1.8
  echo
  out "  ${CYAN}ReGrade doesn't check expectations. It compares behavior.${RST}" 2.6
}

beat_setup() {
  out "${DIM}# two IDENTICAL copies of the same service — there is no version 2${RST}" 0.8
  cmd "docker compose up -d --build"
  out "${GRN} ✓${RST} ${BOLD}instance-a${RST}  Started   ${DIM}:8001  (record)${RST}" 0.5
  out "${GRN} ✓${RST} ${BOLD}instance-b${RST}  Started   ${DIM}:8002  (replay)${RST}" 1.2
  echo
  out "${DIM}# point the existing test suite at ReGrade — one env var, no new tests${RST}" 0.8
  cmd "regrade proxy --target http://localhost:8001 --port 19870 &"
  cmd "BASE_URL=http://localhost:19870 pytest traffic/test_api.py"
  out "${GRN} ✓${RST} 4 passed   ${DIM}(login, read, rename, channels — no security assertions)${RST}" 1.0
  out "${GRN} ✓${RST} Recording ID: ${BOLD}8ad9ece5…${RST}   13 entries" 1.4
  echo
  out "${DIM}# replay against the identical twin${RST}" 0.7
  cmd "regrade replay --rec-id 8ad9ece5 --target http://localhost:8002"
  out "  Requests:      ${BOLD}13${RST}" 0.4
  out "  Total diffs:   ${BOLD}${YEL}15${RST}   ${DIM}(same code — only generated values differ)${RST}" 2.2
}

beat_noise() {
  out "${DIM}# in Claude Code — or any MCP client${RST}" 0.7
  ask "Walk me through my latest ReGrade replay."
  echo
  claude "15 differences, in three groups: ${DIM}(ReGrade MCP)${RST}"
  tool "summarize_deltas(replay_id: b534fe1e…)"
  out "  ${BLUE}\$.token${RST}                  ×3    ${DIM}fresh login token${RST}" 1.0
  out "  ${BLUE}\$.channels[*].created_at${RST}  ×9    ${DIM}boot timestamp${RST}" 1.0
  out "  ${RED}\$.password${RST}               ×3    ${DIM}…a password field?${RST}" 1.8
  echo
  claude "Token and timestamps are expected noise. Map one, drop the other." 1.2
  tool "create_id_mapping(\$.token)  ·  create_filter_rule(DROP created_at)" 2.4
}

beat_twist() {
  out "${DIM}# two of these fields look exactly alike${RST}" 1.0
  echo
  out "  ${BLUE}token${RST}      ${DIM}d9e85964258ee070a0de21d7d4228986${RST}         ${DIM}changes every run${RST}" 1.6
  out "  ${RED}password${RST}   ${DIM}\$2b\$12\$KdvwFHOHgazGdK89DjBXtO…${RST}     ${DIM}changes every run${RST}" 2.0
  echo
  out "  ${DIM}both long, random, different every time. Wave them both off as noise?${RST}" 1.6
  out "  ${CYAN}One is a session token. The other is a secret you must protect.${RST}" 1.6
  out "  ${BOLD}You can't tell by THAT it changed — only by WHAT changed.${RST}" 2.6
}

beat_reveal() {
  out "${DIM}# replay once more, with the profile${RST}" 0.7
  cmd "regrade replay --rec-id 8ad9ece5 --target :8002 --profile hello-security"
  out "  Dropped:   ${BOLD}9${RST} ${DIM}timestamps${RST}      Token:  ${BOLD}${GRN}mapped${RST}   ${DIM}(no longer a diff)${RST}" 1.4
  hr
  out "  ${RED}${BOLD}1 difference remains  →  \$.password${RST}" 1.4
  out "  ${DIM}PATCH /users/2${RST}   ${RED}\$2b\$12\$Kdvw…${RST}   ${DIM}a bcrypt hash, in the response body${RST}" 2.0
  echo
  claude "${BOLD}The rename endpoint leaks the password hash — the shape of CVE-2023-5968.${RST}" 2.4
  claude "Found comparing the app to itself. No security test was ever written." 2.6
}

beat_why() {
  out "${DIM}# seven years of tests never caught it${RST}" 1.2
  echo
  out "  ${DIM}a test can only check what someone ${RST}${BOLD}thought to assert${RST}${DIM}.${RST}" 1.8
  out "  ${CYAN}detecting the ${BOLD}unknown${RST}${CYAN} is a different capability — that's ReGrade.${RST}" 2.4
  echo
  out "  ${BOLD}If your tests could find the bugs they were never written for…${RST}" 1.8
  out "  ${BOLD}what would they find?${RST}" 2.6
}

outro() {
  echo; echo
  out "   ${GRN}${BOLD}✓ a password-hash leak, caught from ordinary traffic${RST}" 1.0
  echo
  out "   ${CYAN}Try it free:${RST}    ${BOLD}curtail.com${RST}   ${DIM}· no card · free every month${RST}" 1.0
  out "   ${CYAN}Run this demo:${RST}  ${BOLD}github.com/Curtail-Inc/hello-ReGrade-security${RST}" 2.4
}

printf '\033[2J\033[3J\033[H'   # clear screen + scrollback so the clip starts fresh
"$@"
