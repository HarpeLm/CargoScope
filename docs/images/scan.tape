# Recording of docs/images/scan.gif with vhs (https://github.com/charmbracelet/vhs).
# Demo project "demo-app": Cargo.toml with chrono = "=0.4.19", serde (derive),
# serde_json and an unused regex = "1"; src/main.rs serializes a timestamp with
# serde_json. In it, run `cargo fetch` and `cargoscope update --fast .` first,
# then `vhs path/to/scan.tape` from that folder with cargoscope on the PATH.
# Colors: macOS Terminal's "Clear Dark" profile; font: SF Mono.
Output "scan.gif"

Set Shell "bash"
Set FontFamily "SF Mono"
Set FontSize 16
Set LineHeight 1.2
Set Width 1100
Set Height 1000
Set Padding 26
Set Margin 34
Set MarginFill "#0d1117"
Set WindowBar Colorful
Set WindowBarSize 38
Set BorderRadius 10
Set TypingSpeed 55ms
Set Theme { "name": "Clear Dark", "background": "#191d27", "foreground": "#e0e0e0", "cursor": "#e0e0e0", "selection": "#273d4c", "black": "#35424c", "red": "#b45648", "green": "#6caa71", "yellow": "#c4ac62", "blue": "#6d96b4", "magenta": "#bd7bcd", "cyan": "#7ccbcd", "white": "#dee5eb", "brightBlack": "#465c6d", "brightRed": "#df6c5a", "brightGreen": "#79be7e", "brightYellow": "#e5c872", "brightBlue": "#67b5ed", "brightMagenta": "#d389e5", "brightCyan": "#84dde0", "brightWhite": "#e5eff5" }

Env PS1 "\[\e[38;5;209m\]❯\[\e[0m\] "

Hide
Type "clear"
Enter
Show

Sleep 700ms
Type "cargoscope scan"
Sleep 500ms
Enter
Sleep 9s
