# The README's demo. Recorded by .github/workflows/demo.yml with VHS
# (https://github.com/charmbracelet/vhs); every key in it is made up.
Output demo.gif

Set Shell "bash"
Set FontSize 18
Set Width 1200
Set Height 680
Set Padding 28
Set Theme "Catppuccin Mocha"
Set TypingSpeed 40ms
Set PlaybackSpeed 1.0

Hide
Type "source demo/setup.sh && clear"
Enter
Sleep 1s
Show

Type "# A project with its keys in a .env file"
Enter
Type "cat .env"
Enter
Sleep 2.5s

Type "# Move them into Cemi's encrypted vault"
Enter
Type "cemi import --discover ~/code"
Enter
Sleep 2s
Type "y"
Enter
Sleep 2.5s
Type "rm .env"
Enter
Sleep 500ms

Type "# cemi.toml only has references: safe to commit"
Enter
Type "grep -A2 '^\[env\]' cemi.toml"
Enter
Sleep 2.5s

Type "# Run with the keys injected, and hidden if anything prints them"
Enter
Type "cemi run -e dev --redact -- ./app.sh"
Enter
Sleep 3s

Type "# Keep what you will need the day it leaks"
Enter
Type `cemi note shop/STRIPE_KEY --purpose "Stripe payments" --rotate "Roll it in the Stripe dashboard"`
Enter
Sleep 1.5s
Type "cemi status"
Enter
Sleep 4s
