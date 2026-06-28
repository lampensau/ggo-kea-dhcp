package web

import (
	"log"
	"net/http"
	"time"
)

// systemCommandDelay is how long we wait after flushing the response before
// taking the box down, so the HTTP reply (and the interstitial it carries)
// reaches the browser first.
const systemCommandDelay = 1500 * time.Millisecond

// handleSystemReboot reboots the appliance. Reachable only in ACTIVE (the
// Settings danger zone), behind a confirm dialog. The box keeps its address, so
// the response is a same-origin reconnect interstitial.
func (s *Server) handleSystemReboot(w http.ResponseWriter, r *http.Request) {
	_ = s.sqlite.LogAudit(s.getActor(r), "SYSTEM_REBOOT", "appliance", "", "", "SUCCESS")
	log.Println("[System] Reboot requested from the danger zone")
	s.respondSystemInterstitial(w,
		"Rebooting appliance…",
		"The appliance is restarting. DHCP is briefly unavailable; this page reconnects on its own once the box is back (about a minute).",
		true)
	deferAfterResponse("reboot", s.net.Reboot)
}

// handleSystemPowerOff powers the appliance off. Terminal "safe to unplug" page,
// no reconnect poll - the box stays off until it is physically power-cycled.
func (s *Server) handleSystemPowerOff(w http.ResponseWriter, r *http.Request) {
	_ = s.sqlite.LogAudit(s.getActor(r), "SYSTEM_POWEROFF", "appliance", "", "", "SUCCESS")
	log.Println("[System] Shutdown requested from the danger zone")
	s.respondSystemInterstitial(w,
		"Appliance shutting down",
		"The appliance is powering off and is safe to unplug once the LEDs settle. Power-cycle the device to use it again.",
		false)
	deferAfterResponse("poweroff", s.net.PowerOff)
}

// deferAfterResponse runs a privileged host command in the background after a
// short delay, so the handler's response flushes before the box goes down.
func deferAfterResponse(label string, fn func() error) {
	go func() {
		time.Sleep(systemCommandDelay)
		if err := fn(); err != nil {
			log.Printf("[System] %s failed: %v", label, err)
		}
	}()
}
