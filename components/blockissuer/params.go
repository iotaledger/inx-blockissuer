package blockissuer

import "github.com/iotaledger/hive.go/app"

type ParametersBlockIssuer struct {
	AccountAddress string `default:"" usage:"the address of the account that is used to issue the blocks"`
	AccountSeed    string `default:"" usage:"the seed of the account that is used to generate the public keypair used to issue blocks"`
}

// ParametersRestAPI contains the definition of the parameters used by the BlockIssuer HTTP server.
type ParametersRestAPI struct {
	// BindAddress defines the bind address on which the BlockIssuer HTTP server listens.
	BindAddress string `default:"localhost:9086" usage:"the bind address on which the Indexer HTTP server listens"`

	// AdvertiseAddress defines the address of the Indexer HTTP server which is advertised to the INX Server (optional).
	AdvertiseAddress string `default:"" usage:"the address of the Indexer HTTP server which is advertised to the INX Server (optional)"`

	// DebugRequestLoggerEnabled defines whether the debug logging for requests should be enabled
	DebugRequestLoggerEnabled bool `default:"false" usage:"whether the debug logging for requests should be enabled"`
}

var ParamsBlockIssuer = &ParametersBlockIssuer{}
var ParamsRestAPI = &ParametersRestAPI{}

var params = &app.ComponentParams{
	Params: map[string]any{
		"blockIssuer": ParamsBlockIssuer,
		"restAPI":     ParamsRestAPI,
	},
	Masked: nil,
}
