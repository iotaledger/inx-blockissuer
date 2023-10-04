package blockissuer

// BlockIssuerInfo is the response to the BlockIssuerAPIRouteInfo endpoint.
type BlockIssuerInfo struct {
	// The account address of the block issuer.
	BlockIssuerAddress string `json:"blockIssuerAddress"`
	// The number of trailing zeroes required for the proof of work to be valid.
	PowTargetTrailingZeros uint8 `json:"powTargetTrailingZeros"`
}
