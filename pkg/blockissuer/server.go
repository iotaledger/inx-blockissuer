package blockissuer

import (
	"crypto/ed25519"

	"github.com/labstack/echo/v4"

	"github.com/iotaledger/inx-app/pkg/nodebridge"
	iotago "github.com/iotaledger/iota.go/v4"
)

type BlockIssuerServer struct {
	nodeBridge             nodebridge.NodeBridge
	accountAddress         *iotago.AccountAddress
	privateKey             ed25519.PrivateKey
	powTargetTrailingZeros uint8
	hrp                    iotago.NetworkPrefix
}

func NewBlockIssuerServer(echoGroup *echo.Group, nodeBridge nodebridge.NodeBridge, accountAddress *iotago.AccountAddress, privateKey ed25519.PrivateKey, powTargetTrailingZeros uint8) *BlockIssuerServer {
	s := &BlockIssuerServer{
		nodeBridge:             nodeBridge,
		accountAddress:         accountAddress,
		privateKey:             privateKey,
		powTargetTrailingZeros: powTargetTrailingZeros,
		hrp:                    nodeBridge.APIProvider().CommittedAPI().ProtocolParameters().Bech32HRP(),
	}

	s.configureRoutes(echoGroup)

	return s
}
