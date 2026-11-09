# VHS tape: edit -> hook nudge -> /sift:review -> report.
# Requires the sift plugin to be installed (see README: /plugin marketplace add + /plugin install).
# Drives a live, logged-in Claude Code session and spends real tokens.
# Run from the repository root: vhs docs/media/demo.tape

Output docs/media/hook.gif

Require claude
Require sift

Set Shell "bash"
Set FontSize 15
Set Width 1400
Set Height 850
Set TypingSpeed 35ms

Hide
Type "git worktree remove --force /tmp/sift-demo 2>/dev/null; git worktree add -q --detach /tmp/sift-demo main && cd /tmp/sift-demo/examples/flight-offers && clear"
Enter
Sleep 2s
Show

Type "claude"
Enter
Sleep 8s

Type "In OfferRepository.search, concatenate origin and destination into the SQL string instead of binding them."
Enter
# The Edit runs here, then the hook reports the new high-severity finding.
Sleep 75s

Type "/sift:review main"
Enter
Sleep 150s

Type "/exit"
Enter
Sleep 2s