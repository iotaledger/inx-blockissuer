package daemon

const (
	PriorityDisconnectINX = iota // no dependencies
	PriorityStopBlockIssuer
	PriorityStopBlockIssuerAPI
)
