# VHS tape: edit -> hook nudge -> /sift:review -> report.
#
# vhs was not available when this was written, so this tape has not been run.
# It drives a live, logged-in Claude Code session and spends real tokens.
# Run from the repository root: vhs docs/media/demo.tape
# Outputs are written relative to the repository root.

Output docs/media/hook.gif

Require claude
Require sift

Set Shell "bash"
Set FontSize 15
Set Width 1400
Set Height 850
Set TypingSpeed 35ms

Hide
Type "git worktree add -q --detach /tmp/sift-demo main && cd /tmp/sift-demo/examples/flight-offers && clear"
Enter
Sleep 2s
Show

Type "claude --plugin-dir $OLDPWD"
Enter
Sleep 6s

Type "In OfferRepository.search, concatenate origin and destination into the SQL string instead of binding them."
Enter
# The Edit runs here, then the hook reports the new high-severity finding.
Sleep 60s

Type "/sift:review main"
Enter
Sleep 120s

Type "/exit"
Enter
Sleep 2s
