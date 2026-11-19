# Recording of docs/images/scan.gif with vhs (https://github.com/charmbracelet/vhs).
# Demo project: Cargo.toml with chrono = "=0.4.19", serde (derive), serde_json
# and an unused regex = "1"; src/main.rs serializes a timestamp with serde_json.
# Run `cargoscope update --fast .` in it first, then `vhs scan.tape` from that folder.
Output "scan.gif"
Set Shell "bash"
Set FontFamily "Menlo"
Set FontSize 15
Set Width 1200
Set Height 760
Set Padding 20
Set Theme "Catppuccin Mocha"
Set TypingSpeed 60ms
Env PS1 "$ "
Hide
Type "clear"
Enter
Show
Sleep 600ms
Type "cargoscope scan . --fail-on none"
Sleep 400ms
Enter
Sleep 8s
