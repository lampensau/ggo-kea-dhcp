package web

import (
	"fmt"
	"io"
	"net/http"
)

// respondInterstitial writes the reconnect interstitial as a full-page response.
// Used by the settings and reset flows that re-IP eth0 - both native POST forms,
// so the browser navigates and replaces the document (the setup apply flushes it
// directly).
func (s *Server) respondInterstitial(w http.ResponseWriter, targetIP string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, interstitialHTML(targetIP))
}

// respondSystemInterstitial writes a self-contained full-page response for a
// reboot or shutdown from the danger zone. Reboot (poll=true) keeps the box's
// current address - unlike the re-IP flows - so it polls the SAME origin and
// returns to the dashboard once the box comes back. Shutdown (poll=false) is a
// terminal "safe to power off" page with no poll.
func (s *Server) respondSystemInterstitial(w http.ResponseWriter, title, body string, poll bool) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, systemInterstitialHTML(title, body, poll))
}

// systemInterstitialHTML builds the reboot/shutdown page. The reboot poll only
// redirects after it has first seen the origin go DOWN and then come back - the
// box stays reachable for a second or two after we respond (we delay the actual
// reboot so this page can flush), and redirecting during that window would just
// drop the user onto a dashboard that is about to die.
func systemInterstitialHTML(title, body string, poll bool) string {
	const style = `<style>
 #ggo-reconnect{font-family:system-ui,sans-serif;position:fixed;inset:0;background:#0e1116;color:#e6e9ee;display:flex;align-items:center;justify-content:center;z-index:9999}
 #ggo-reconnect .card{max-width:30rem;padding:2rem;background:#161b22;border:1px solid #2b333d;border-radius:.5rem;text-align:center}
 #ggo-reconnect .spin{width:2.5rem;height:2.5rem;border:.25rem solid #2b333d;border-top-color:#3fb950;border-radius:50%;margin:0 auto 1.25rem;animation:ggospin 1s linear infinite}
 @keyframes ggospin{to{transform:rotate(360deg)}}
</style>`
	spinner := ""
	script := ""
	if poll {
		spinner = `<div class="spin"></div>`
		script = `<script>
 (function(){
   var loc = window.location;
   var base = loc.protocol + "//" + loc.host;   // same origin: a reboot keeps the IP
   var done = false, wentDown = false, tries = 0;
   function go(){ if (done) return; done = true; window.location.href = base + "/dashboard"; }
   function probe(){
     if (done) return;
     tries++;
     var s = document.createElement("link");
     s.rel = "stylesheet";
     s.onload = function(){ s.remove(); if (wentDown) go(); };   // only return once it actually came back
     s.onerror = function(){ s.remove(); wentDown = true; };
     s.href = base + "/static/style.css?probe=" + Date.now();
     document.head.appendChild(s);
     if (tries * 2 >= 240) { go(); }   // hard fallback after ~4 min
   }
   setInterval(probe, 2000);
   probe();
 })();
</script>`
	}
	return fmt.Sprintf(`%s
<div id="ggo-reconnect"><div class="card">
 %s
 <h2>%s</h2>
 <p>%s</p>
</div></div>%s`, style, spinner, title, body, script)
}

// interstitialHTML returns a self-contained page that polls the new gateway
// address (which the client can only reach after it gets a fresh DHCP lease in
// the new subnet) and redirects to the dashboard once it answers.
func interstitialHTML(newIP string) string {
	// Returned as a full-page response to a native POST navigation: the browser
	// replaces the document and executes the embedded script.
	return fmt.Sprintf(`<style>
 #ggo-reconnect{font-family:system-ui,sans-serif;position:fixed;inset:0;background:#0e1116;color:#e6e9ee;display:flex;align-items:center;justify-content:center;z-index:9999}
 #ggo-reconnect .card{max-width:30rem;padding:2rem;background:#161b22;border:1px solid #2b333d;border-radius:.5rem;text-align:center}
 #ggo-reconnect .spin{width:2.5rem;height:2.5rem;border:.25rem solid #2b333d;border-top-color:#3fb950;border-radius:50%%;margin:0 auto 1.25rem;animation:ggospin 1s linear infinite}
 @keyframes ggospin{to{transform:rotate(360deg)}}
 #ggo-recovery{display:none;margin-top:1.25rem;padding:1rem;background:#3a2e10;border-radius:.5rem;font-size:.9rem}
 #ggo-reconnect code{font-family:ui-monospace,Menlo,Consolas,monospace;background:#0e1116;padding:.1rem .4rem;border-radius:.25rem}
</style>
<div id="ggo-reconnect"><div class="card">
 <div class="spin"></div>
 <h2>Applying network profile…</h2>
 <p>The appliance is switching to its new address. Your computer needs a new IP from the new subnet - this usually takes a few seconds.</p>
 <div id="ggo-recovery">
   Couldn't reach the new gateway automatically. Verify your computer received a new IP address (or reconnect to the management AP), then browse to
   <code id="ggo-recovery-url"></code>.
 </div>
</div></div>
<script>
 (function(){
   // Reconnect on the SAME scheme+port the browser is already using (behind Caddy that's
   // https/443 with an empty port; in dev it's http:8080) - never the app's internal bind
   // port, which leaks ":8080" through the reverse proxy. Swap the HOST to the new IP only
   // when we're on the literal old numeric IP; if we arrived via an mDNS / DNS hostname
   // (e.g. ggo-kea-dhcp.local) keep it - the name re-resolves to the box's new address by
   // itself and the existing per-name cert keeps working, so there's nothing to swap.
   var loc = window.location;
   var onLiteralIP = /^\d{1,3}(\.\d{1,3}){3}$/.test(loc.hostname);
   var host = onLiteralIP ? "%s" : loc.hostname;
   var base = loc.protocol + "//" + host + (loc.port ? ":" + loc.port : "");
   var target = base + "/dashboard";
   var rec = document.getElementById("ggo-recovery-url"); if (rec) rec.textContent = target;
   var done = false, tries = 0;
   function go(){ if (done) return; done = true; window.location.href = target; }
   // Cross-origin reachability probe via a stylesheet load: a <link> is not
   // subject to CORS, so onload fires the moment the new server answers (fetch
   // no-cors is unreliable from a now-dead origin). Re-loading style.css is
   // harmless.
   function probe(){
     if (done) return;
     tries++;
     var s = document.createElement("link");
     s.rel = "stylesheet";
     s.onload = function(){ s.remove(); go(); };
     s.onerror = function(){ s.remove(); };
     s.href = base + "/static/style.css?probe=" + Date.now();
     document.head.appendChild(s);
     if (tries * 2 >= 15) { var el = document.getElementById("ggo-recovery"); if (el) el.style.display = "block"; }
     if (tries * 2 >= 30) { go(); } // hard fallback: navigate anyway after ~30s
   }
   setInterval(probe, 2000);
   probe();
 })();
</script>`, newIP)
}
