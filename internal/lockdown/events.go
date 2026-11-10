package lockdown

import "github.com/blechschmidt/pullthrough-security/internal/notify"

// lockdownEvent builds the notification for a lockdown transition. For a
// "cleared"/"expired" transition the previous mode is the meaningful one, which
// the caller passes via st.Mode.
func lockdownEvent(action string, st State, _ Mode) notify.Event {
	return notify.LockdownEvent(action, string(st.Mode), st.IncidentID, st.Operator, st.Reason, len(st.Targets))
}
