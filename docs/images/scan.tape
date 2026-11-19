# Recording of docs/images/scan.gif with vhs (https://github.com/charmbracelet/vhs).
# Demo project "demo-app": Cargo.toml with chrono = "=0.4.19", serde (derive),
# serde_json and an unused regex = "1"; src/main.rs serializes a timestamp with
# serde_json. In it, run `cargo fetch` and `cargoscope update --fast .` first,
# then `vhs path/to/scan.tape` from that folder with cargoscope on the PATH.
Output "scan.gif"

Set Shell "bash"
Set FontFamily "Menlo"
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
Set Theme { "name": "CargoScope", "background": "#161b22", "foreground": "#e6edf3", "cursor": "#e6edf3", "selection": "#30363d", "black": "#484f58", "red": "#ff7b72", "green": "#7ee787", "yellow": "#e3b341", "blue": "#79c0ff", "magenta": "#d2a8ff", "cyan": "#56d4dd", "white": "#b1bac4", "brightBlack": "#6e7681", "brightRed": "#ffa198", "brightGreen": "#aff5b4", "brightYellow": "#f2cc60", "brightBlue": "#a5d6ff", "brightMagenta": "#e2c5ff", "brightCyan": "#b3f0ff", "brightWhite": "#f0f6fc" }

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
