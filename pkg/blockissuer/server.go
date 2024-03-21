package blockissuer

import (
	"crypto/ed25519"

	"github.com/labstack/echo/v4"

	"github.com/iotaledger/hive.go/ierrors"
	"github.com/iotaledger/inx-app/pkg/nodebridge"
	iotago "github.com/iotaledger/iota.go/v4"
	"github.com/iotaledger/iota.go/v4/nodeclient"
)

//nolint:revive // better to be explicit here
type BlockIssuerServer struct {
	nodeBridge             nodebridge.NodeBridge
	accountAddress         *iotago.AccountAddress
	privateKey             ed25519.PrivateKey
	powTargetTrailingZeros uint8

	hrp        iotago.NetworkPrefix
	nodeClient *nodeclient.Client
}

func NewBlockIssuerServer(echoGroup *echo.Group, nodeBridge nodebridge.NodeBridge, accountAddress *iotago.AccountAddress, privateKey ed25519.PrivateKey, powTargetTrailingZeros uint8) (*BlockIssuerServer, error) {
	nodeClient, err := nodeBridge.INXNodeClient()
	if err != nil {
		return nil, ierrors.Wrap(err, "failed to get INX node client")
	}

	s := &BlockIssuerServer{
		nodeBridge:             nodeBridge,
		accountAddress:         accountAddress,
		privateKey:             privateKey,
		powTargetTrailingZeros: powTargetTrailingZeros,
		hrp:                    nodeBridge.APIProvider().CommittedAPI().ProtocolParameters().Bech32HRP(),
		nodeClient:             nodeClient,
	}

	s.configureRoutes(echoGroup)

	return s, nil
}
