package main

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"sync"
	"time"
)

// Stream tickets. EventSource cannot send an Authorization header, so an
// admin page used to open /api/events?admin_token=<its 24 h session>: the
// session sat in the URL, which proxies and CDNs write to their logs (the
// China line of xhh.li goes through a third-party CDN), and whoever read the
// log held the admin session for a day. The page now trades its session for
// a ticket (POST /api/auth/stream-ticket, Bearer) and opens the stream with
// ?ticket=: a ticket works once, within streamTicketTTL, and only stands for
// the session it was made from, which the stream keeps checking as before. A
// logged ticket is spent. admin_token still works for pages that do not ask
// for tickets (Pulse-Hotaru's).
const (
	streamTicketTTL = 30 * time.Second
	streamTicketMax = 4096 // outstanding tickets; more are refused until some expire
)

type streamTicket struct {
	token   string
	expires time.Time
}

var (
	streamTicketsMu sync.Mutex
	streamTickets   = make(map[string]streamTicket)
)

func issueStreamTicket(token string, now time.Time) (string, bool) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", false
	}
	t := hex.EncodeToString(b)
	streamTicketsMu.Lock()
	defer streamTicketsMu.Unlock()
	if len(streamTickets) >= streamTicketMax {
		for k, v := range streamTickets {
			if now.After(v.expires) {
				delete(streamTickets, k)
			}
		}
		if len(streamTickets) >= streamTicketMax {
			return "", false
		}
	}
	streamTickets[t] = streamTicket{token: token, expires: now.Add(streamTicketTTL)}
	return t, true
}

// redeemStreamTicket spends a ticket and returns the session it stands for.
func redeemStreamTicket(t string, now time.Time) (string, bool) {
	if t == "" {
		return "", false
	}
	streamTicketsMu.Lock()
	v, ok := streamTickets[t]
	delete(streamTickets, t)
	streamTicketsMu.Unlock()
	if !ok || now.After(v.expires) {
		return "", false
	}
	return v.token, true
}

func handleStreamTicket(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	token := bearerToken(r)
	if !authTokenValid(token) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	t, ok := issueStreamTicket(token, time.Now())
	if !ok {
		http.Error(w, "too many stream tickets", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"ticket": t, "expires_in": int(streamTicketTTL / time.Second)})
}
