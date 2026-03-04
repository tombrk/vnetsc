package main

import (
	"bytes"
	"io"

	mdns "github.com/miekg/dns"

	"gvisor.dev/gvisor/pkg/tcpip"
)

// dnsEndpoint intercepts DNS traffic. Forwards all queries to the
// guest's configured DNS server, but strips AAAA records from responses
// to force IPv4-only resolution.
type dnsEndpoint struct {
	tcpip.Endpoint
}

func (de *dnsEndpoint) Write(p tcpip.Payloader, opts tcpip.WriteOptions) (int64, tcpip.Error) {
	// Read the full query payload.
	raw, err := io.ReadAll(p)
	if err != nil || len(raw) == 0 {
		return 0, &tcpip.ErrBadBuffer{}
	}

	msg := new(mdns.Msg)
	if msg.Unpack(raw) == nil {
		for _, q := range msg.Question {
			vlog("DNS Q: %s %s", q.Name, mdns.TypeToString[q.Qtype])
		}
	}

	// Forward all queries (including AAAA) — we strip AAAA from Read responses.
	return de.Endpoint.Write(bytes.NewReader(raw), opts)
}

func (de *dnsEndpoint) Connect(addr tcpip.FullAddress) tcpip.Error {
	vlog("DNS Connect → %v:%d (passthrough)", addr.Addr, addr.Port)
	return de.Endpoint.Connect(addr)
}

func (de *dnsEndpoint) Read(w io.Writer, opts tcpip.ReadOptions) (tcpip.ReadResult, tcpip.Error) {
	var buf bytes.Buffer
	res, tcpErr := de.Endpoint.Read(&buf, opts)
	if tcpErr != nil {
		return res, tcpErr
	}

	raw := stripAAAA(buf.Bytes())
	n2, _ := w.Write(raw)
	res.Count = n2
	res.Total = n2
	return res, nil
}


// stripAAAA removes AAAA records from a DNS response.
// If the query was for AAAA, returns an empty NOERROR response
// (no answers at all, not even CNAMEs) so resolvers don't get confused.
func stripAAAA(raw []byte) []byte {
	msg := new(mdns.Msg)
	if msg.Unpack(raw) != nil {
		return raw // can't parse, pass through
	}

	// Check if this is a response to an AAAA query.
	isAAAAQuery := false
	for _, q := range msg.Question {
		if q.Qtype == mdns.TypeAAAA {
			isAAAAQuery = true
			break
		}
	}

	if isAAAAQuery {
		// Return empty answer — no AAAA, no CNAME, just NOERROR.
		msg.Answer = nil
		msg.Ns = nil
		msg.Extra = nil
		out, err := msg.Pack()
		if err != nil {
			return raw
		}
		return out
	}

	// For non-AAAA queries, strip any stray AAAA records from answers.
	filtered := make([]mdns.RR, 0, len(msg.Answer))
	for _, rr := range msg.Answer {
		if _, isAAAA := rr.(*mdns.AAAA); !isAAAA {
			filtered = append(filtered, rr)
		}
	}
	if len(filtered) == len(msg.Answer) {
		return raw // nothing to strip
	}

	msg.Answer = filtered
	out, err := msg.Pack()
	if err != nil {
		return raw
	}
	return out
}

var _ tcpip.Endpoint = (*dnsEndpoint)(nil)
