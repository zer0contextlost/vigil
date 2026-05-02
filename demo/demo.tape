# vigil demo tape
Output demo.gif
Set FontSize 14
Set Width 1200
Set Height 700
Set Theme "Dracula"
Set Padding 20

# Show the tool name
Type "# vigil — runtime AI agent monitor"
Sleep 1s
Enter
Sleep 500ms

# Init
Type "vigil init"
Enter
Sleep 2s

# Show the generated policy
Type "cat .agent-sentinel.yaml"
Enter
Sleep 2s

# Run the demo agent
Type "vigil run -- bash demo/mock-agent.sh"
Enter
Sleep 1s

# Watch events stream in (mock agent runs)
Sleep 8s

# Quit
Type "q"
Sleep 500ms

# Show sessions
Type "vigil sessions"
Enter
Sleep 2s
