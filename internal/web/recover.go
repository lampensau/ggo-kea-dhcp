package web

import (
	"fmt"
	"log"
)

// runRecovered runs fn, logging and absorbing a panic. Background goroutines
// (ticks, probes, the boot reconcile) don't get the net/http per-connection
// recovery, so without this a panic in any of them kills the whole process -
// DHCP management, DNS, and the UI together. A skipped cycle is the correct
// degradation; the next tick retries.
func runRecovered(name string, fn func()) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[%s] recovered from panic: %v", name, r)
		}
	}()
	fn()
}

// runRecoveredAudited is runRecovered for the detached reconcile goroutines
// (finish-apply/switch, held reconciles, uplink connect, zone prime). A panic
// there strands the box mid-transition, so besides absorbing it the recovery is
// audited - Diagnostics is often the only place an operator can see why an
// apply never finished. fn's own defers (endReconcile) run during unwinding,
// before the recover here, so the mutation guard is always released.
func (r *reconciler) runRecoveredAudited(name string, fn func()) {
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("[%s] recovered from panic: %v", name, rec)
			_ = r.sqlite.LogAudit("SYSTEM", "PANIC_RECOVERED", name, "", fmt.Sprint(rec), "ERROR")
		}
	}()
	fn()
}

// runRecoveredReconcile is runRecoveredAudited for the goroutines that own a
// lifecycle transition (finish-apply, finish-switch). A crash there used to be
// self-healing - systemd restarted the process and the boot reconcile completed
// or reverted the interrupted apply within seconds. Absorbing the panic removes
// that restart, so recovery kicks ONE background converge instead: the box is
// likely stranded in persisted CONFIGURING with monitors and DNS already torn
// down, and the converge dispatches straight into resumeInterruptedApply. The
// kicked converge runs under the plain recover wrapper - a second panic there
// is absorbed without kicking again, so this cannot loop.
func (r *reconciler) runRecoveredReconcile(name string, fn func()) {
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("[%s] recovered from panic: %v", name, rec)
			_ = r.sqlite.LogAudit("SYSTEM", "PANIC_RECOVERED", name, "", fmt.Sprint(rec), "ERROR")
			go runRecovered(name+"-recovery", func() {
				if !r.beginReconcile() {
					return // another reconcile is running; it converges the state
				}
				defer r.endReconcile()
				if err := r.ReconcileApplianceState(ModeConverge, 0); err != nil {
					log.Printf("[%s-recovery] converge after panic: %v", name, err)
					_ = r.sqlite.LogAudit("SYSTEM", "RECONCILE_FAILED", name+"-recovery", "", err.Error(), "WARNING")
				}
			})
		}
	}()
	fn()
}
