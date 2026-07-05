package dns

import "strings"

// DNS wire-format constants (RFC 1035).
const (
	headerLen = 12

	typeA   = 1
	typePTR = 12
	typeANY = 255

	classIN = 1

	rcodeNoError  = 0
	rcodeNXDomain = 3
	rcodeServFail = 2
	rcodeRefused  = 5
)

// maxUDPResponse is the classic pre-EDNS0 UDP payload cap. This server never
// negotiates a larger size for its own answers; anything over gets the TC bit.
const maxUDPResponse = 512

// question is the parsed first (and only honored) question of a query.
type question struct {
	Name  string // lowercase FQDN without trailing dot, e.g. "bpx-19.inv.greengo.digital"
	Type  uint16
	Class uint16
	end   int // offset just past the question section, for verbatim echo
}

// parseQuestion decodes the header and first question of msg. It returns ok=false
// for anything that cannot be safely answered: a short packet, a zero question
// count, or a name that fails to decode. Parsing is pure and deterministic - the
// fuzz test double-parses to assert that.
func parseQuestion(msg []byte) (question, bool) {
	var q question
	if len(msg) < headerLen {
		return q, false
	}
	if qdcount := int(msg[4])<<8 | int(msg[5]); qdcount < 1 {
		return q, false
	}
	name, off, ok := decodeName(msg, headerLen)
	if !ok || off+4 > len(msg) {
		return q, false
	}
	q.Name = name
	q.Type = uint16(msg[off])<<8 | uint16(msg[off+1])
	q.Class = uint16(msg[off+2])<<8 | uint16(msg[off+3])
	q.end = off + 4
	return q, true
}

// decodeName reads a possibly-compressed domain name starting at off, returning
// the lowercase dotted name (no trailing dot) and the offset just past the name
// in the ORIGINAL stream (i.e. past the first pointer if one was followed).
// Compression pointers are bounded - a pointer loop or a name past the 255-octet
// limit fails the parse instead of spinning.
func decodeName(msg []byte, off int) (string, int, bool) {
	var b strings.Builder
	end := -1 // resume offset in the original stream; set at the first pointer
	jumps := 0
	total := 0
	for {
		if off >= len(msg) {
			return "", 0, false
		}
		c := int(msg[off])
		switch {
		case c == 0:
			if end < 0 {
				end = off + 1
			}
			return b.String(), end, true
		case c&0xc0 == 0xc0: // compression pointer
			if off+1 >= len(msg) {
				return "", 0, false
			}
			if jumps++; jumps > 16 {
				return "", 0, false // pointer loop
			}
			if end < 0 {
				end = off + 2
			}
			off = (c&0x3f)<<8 | int(msg[off+1])
		case c&0xc0 != 0:
			return "", 0, false // 0x40/0x80 label types are not supported
		default: // plain label
			if off+1+c > len(msg) {
				return "", 0, false
			}
			if total += c + 1; total > 255 {
				return "", 0, false
			}
			if b.Len() > 0 {
				b.WriteByte('.')
			}
			for _, ch := range msg[off+1 : off+1+c] {
				if ch >= 'A' && ch <= 'Z' {
					ch += 'a' - 'A'
				}
				b.WriteByte(ch)
			}
			off += 1 + c
		}
	}
}

// encodeName renders a dotted name as uncompressed wire-format labels. Empty
// labels (from stray dots) are dropped; an oversized label is truncated at the
// 63-octet limit rather than emitting an invalid length byte.
func encodeName(name string) []byte {
	out := make([]byte, 0, len(name)+2)
	for label := range strings.SplitSeq(name, ".") {
		if label == "" {
			continue
		}
		if len(label) > 63 {
			label = label[:63]
		}
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	return append(out, 0)
}

// respond builds a response for req/q: the echoed question, then answers (already
// wire-encoded RRs, typically one - minimal answers by design). aa marks
// authoritative data; rcode carries NXDOMAIN/SERVFAIL/REFUSED. Oversized
// responses are cut back to the question with the TC bit set (UDP-only stance:
// the client retries over TCP against a real resolver, or accepts the loss).
func respond(req []byte, q question, rcode byte, aa bool, answers ...[]byte) []byte {
	resp := make([]byte, 0, maxUDPResponse)
	resp = append(resp, req[0], req[1])              // transaction id
	flags1 := byte(0x80) | req[2]&0x78 | req[2]&0x01 // QR, opcode + RD echoed
	if aa {
		flags1 |= 0x04
	}
	resp = append(resp, flags1, 0x80|rcode&0x0f) // RA set: we forward upstream when one exists
	resp = append(resp, 0, 1)                    // QDCOUNT
	resp = append(resp, 0, byte(len(answers)))   // ANCOUNT
	resp = append(resp, 0, 0, 0, 0)              // NSCOUNT, ARCOUNT
	resp = append(resp, req[headerLen:q.end]...) // question echoed verbatim
	for _, a := range answers {
		resp = append(resp, a...)
	}
	if len(resp) > maxUDPResponse {
		resp = resp[:headerLen+(q.end-headerLen)]
		resp[2] |= 0x02         // TC
		resp[6], resp[7] = 0, 0 // ANCOUNT = 0
	}
	return resp
}

// rrA builds one A record pointing at the echoed question name (0xc00c).
func rrA(ip [4]byte, ttl uint32) []byte {
	rr := []byte{0xc0, 0x0c, 0, typeA, 0, classIN}
	rr = appendTTL(rr, ttl)
	rr = append(rr, 0, 4)
	return append(rr, ip[:]...)
}

// rrPTR builds one PTR record pointing the echoed question name at target.
func rrPTR(target string, ttl uint32) []byte {
	rdata := encodeName(target)
	rr := []byte{0xc0, 0x0c, 0, typePTR, 0, classIN}
	rr = appendTTL(rr, ttl)
	rr = append(rr, byte(len(rdata)>>8), byte(len(rdata)))
	return append(rr, rdata...)
}

func appendTTL(b []byte, ttl uint32) []byte {
	return append(b, byte(ttl>>24), byte(ttl>>16), byte(ttl>>8), byte(ttl))
}

// reverseName parses an in-addr.arpa PTR question name back into the IPv4
// address it reverses, e.g. "9.0.0.10.in-addr.arpa" -> 10.0.0.9.
func reverseName(name string) ([4]byte, bool) {
	rest, ok := strings.CutSuffix(name, ".in-addr.arpa")
	if !ok {
		return [4]byte{}, false
	}
	parts := strings.Split(rest, ".")
	if len(parts) != 4 {
		return [4]byte{}, false
	}
	var ip [4]byte
	for i, p := range parts {
		n, ok := atoiOctet(p)
		if !ok {
			return [4]byte{}, false
		}
		ip[3-i] = n // PTR labels are least-significant first
	}
	return ip, true
}

// atoiOctet parses a decimal 0-255 label without accepting signs, spaces, or
// leading-zero ambiguity beyond what strconv would (it is stricter: digits only).
func atoiOctet(s string) (byte, bool) {
	if len(s) == 0 || len(s) > 3 {
		return 0, false
	}
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	if n > 255 {
		return 0, false
	}
	return byte(n), true
}
