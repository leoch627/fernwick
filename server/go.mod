module work.starrail/client/server

go 1.26.0

require work.starrail/client/desktop v0.0.0

require (
	filippo.io/age v1.3.2 // indirect
	filippo.io/hpke v0.4.0 // indirect
	github.com/Microsoft/go-winio v0.6.2 // indirect
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
)

// Tests check payloads with the client's own verifiers; the server binary does not import it.
replace work.starrail/client/desktop => ../desktop
