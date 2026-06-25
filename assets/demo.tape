# SentinelDeck animated demo.
#
# Generate the GIF with charmbracelet/vhs (https://github.com/charmbracelet/vhs):
#
#   vhs assets/demo.tape        ->  writes assets/demo.gif
#
# Then swap the static assets/cli.svg in README.md for assets/demo.gif.
# Requires sentineldeck on PATH (pip install -e . or pipx install sentineldeck)
# and network access for the live scan.

Output assets/demo.gif

Set Shell "bash"
Set FontSize 16
Set Width 1200
Set Height 760
Set Padding 24
Set Theme "Catppuccin Mocha"
Set TypingSpeed 60ms

# 1. The branded home screen (instant, no network).
Type "sentineldeck"
Enter
Sleep 3s

# 2. A real passive scan turning a domain into a grade and findings.
Type "sentineldeck scan example.com"
Enter
Sleep 8s

# 3. Render a client-ready HTML report.
Type "sentineldeck scan example.com --html report.html"
Enter
Sleep 5s
