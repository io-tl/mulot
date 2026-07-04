# Command injection (Go)

Go has no shell by default — `exec.Command("ls", arg)` passes args directly with
NO shell parsing, so it is injection-safe. The bug appears only when code invokes
a shell: `exec.Command("sh","-c", userInput)`, `exec.Command("bash","-c",
fmt.Sprintf(...))`, or builds the arg string with user data. Common around:
ping/traceroute tools, image/video conversion (ffmpeg/imagemagick), git/archive
ops, PDF/report generation, backup/export.

1. **Find the sink**: features that "run", "convert", "ping", "lookup", export,
   or take a hostname/filename/format string.
2. **Probe** with shell metacharacters in that field (`http_request` or the
   form): `; id`, `| id`, `$(id)`, backtick-id, `& id`, newline `%0aid`. A blind
   sink won't echo — go time-based: `; sleep 5` and compare round-trip latency,
   or `$(sleep 5)`.
3. **Sweep** the separators in ONE `http_fuzz` (marker after a benign value),
   `payloads:[";id","|id","$(id)","%0aid","&&id","||id"]`,
   `match_regex:"uid=[0-9]+\\("` to flag command output in the body.
4. **Argument injection** (no shell, but the binary parses flags): if input
   becomes a CLI argument, smuggle a flag — a filename `--output=/tmp/x`, tar
   `--checkpoint-action=exec=...`, curl `-o`/`-K`. Test values starting with `-`.
5. **Windows target** (`cmd /C`): same bug class, different separators —
   `&whoami`, `|whoami`, `&&whoami`; no `$()`/backtick support on cmd.exe.

Evidence: command output (`uid=...`) in the response, or a reproducible time
delay from `sleep`.
Remediation: avoid the shell — call `exec.Command(bin, args...)` with a fixed
binary and separate args, never `sh -c` with concatenated input; validate
against a strict allowlist; reject argument values beginning with `-` (or pass
`--` to stop flag parsing).
