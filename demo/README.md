# Recording the Vigil Demo

The goal: a 60-90 second GIF showing vigil catching a prompt-injection-driven destructive shell call in real time.

## Prerequisites

- `vhs` (https://github.com/charmbracelet/vhs) for terminal recording
- `vigil` built and in PATH: `cargo install --path crates/vigil-cli`
- A sample project directory

## What the demo shows

1. User runs `vigil init` → policy file generated
2. User runs `vigil run -- bash demo/mock-agent.sh`  
3. TUI launches, shows live events
4. Mock agent reads a file → FSREAD event appears (gray)
5. Mock agent makes a fake LLM call → LLM_REQ/LLM_RES appear (blue/cyan)
6. Mock agent triggers a destructive shell command → BLOCKED appears in RED + BOLD
7. Session ends, cost summary printed
8. User runs `vigil sessions` → sees the saved session
9. User runs `vigil replay <id>` → watches it back

## Recording with vhs

```bash
# Install vhs if you don't have it
brew install charmbracelet/tap/vhs  # macOS
# or visit https://github.com/charmbracelet/vhs#installation for other systems

# Set up the demo directory
chmod +x demo/mock-agent.sh

# Record the tape
vhs < demo/demo.tape

# Output: demo.gif (ready to embed in README.md)
```

## Customizing the demo

Edit `demo.tape` to adjust:
- `Set FontSize` — larger for visibility, smaller to fit more content
- `Set Width` / `Set Height` — GIF dimensions
- `Sleep` durations — to match actual tool performance on your machine
- `Type` commands — to show different vigil features

Rerun `vhs < demo.tape` after changes.

## Tips for a great demo

- Run it on a clean terminal with no distracting output above
- Make sure the mock agent runs in under 10 seconds (adjust sleeps in `mock-agent.sh`)
- Test on your target machine — timing can vary
- The RED BLOCKED message is the payoff — give it time to be visible
