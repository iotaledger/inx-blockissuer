package blockissuer

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"go.uber.org/dig"

	"github.com/iotaledger/hive.go/app"
	"github.com/iotaledger/hive.go/app/shutdown"
	"github.com/iotaledger/hive.go/crypto"
	"github.com/iotaledger/hive.go/ierrors"
	"github.com/iotaledger/inx-app/pkg/httpserver"
	"github.com/iotaledger/inx-app/pkg/nodebridge"
	"github.com/iotaledger/inx-blockissuer/pkg/daemon"
	iotago "github.com/iotaledger/iota.go/v4"
)

const APIRoute = "/api/blockissuer/v1"

func init() {
	Component = &app.Component{
		Name:     "BlockIssuer",
		DepsFunc: func(cDeps dependencies) { deps = cDeps },
		Params:   params,
		Provide:  provide,
		Run:      run,
	}
}

type dependencies struct {
	dig.In
	NodeBridge      *nodebridge.NodeBridge
	AccountAddress  *iotago.AccountAddress
	PrivateKey      ed25519.PrivateKey
	ShutdownHandler *shutdown.ShutdownHandler
	Echo            *echo.Echo
}

var (
	Component *app.Component
	deps      dependencies
)

func provide(c *dig.Container) error {
	type depsIn struct {
		dig.In
		NodeBridge *nodebridge.NodeBridge
	}

	if err := c.Provide(func(deps depsIn) (*iotago.AccountAddress, error) {
		if ParamsBlockIssuer.AccountAddress == "" {
			return nil, ierrors.Errorf("empty bech32 in config")
		}

		hrp, addr, err := iotago.ParseBech32(ParamsBlockIssuer.AccountAddress)
		if err != nil {
			return nil, ierrors.Wrapf(err, "invalid bech32 address: %s", ParamsBlockIssuer.AccountAddress)
		}

		if deps.NodeBridge.APIProvider().CommittedAPI().ProtocolParameters().Bech32HRP() != hrp {
			return nil, ierrors.Wrapf(err, "invalid bech32 address prefix: %s", hrp)
		}

		accountAddr, ok := addr.(*iotago.AccountAddress)
		if !ok {
			return nil, ierrors.Errorf("invalid bech32 address, not an account: %s", ParamsBlockIssuer.AccountAddress)
		}

		return accountAddr, nil
	}); err != nil {
		return err
	}

	if err := c.Provide(func() (ed25519.PrivateKey, error) {
		privateKeys, err := loadEd25519PrivateKeysFromEnvironment("BLOCKISSUER_PRV_KEY")
		if err != nil {
			return nil, ierrors.Errorf("loading block issuer private key failed, err: %w", err)
		}

		if len(privateKeys) == 0 {
			return nil, ierrors.New("loading block issuer private key failed, err: no private keys given")
		}

		if len(privateKeys) > 1 {
			return nil, ierrors.New("loading block issuer private key failed, err: too many private keys given")
		}

		privateKey := privateKeys[0]
		if len(privateKey) != ed25519.PrivateKeySize {
			return nil, ierrors.New("loading block issuer private key failed, err: wrong private key length")
		}

		return privateKey, nil
	}); err != nil {
		return err
	}

	return c.Provide(func() *echo.Echo {
		return httpserver.NewEcho(
			Component.Logger(),
			nil,
			ParamsRestAPI.DebugRequestLoggerEnabled,
		)
	})
}

func run() error {
	// create a background worker that handles the API
	if err := Component.Daemon().BackgroundWorker("API", func(ctx context.Context) {
		Component.LogInfo("Starting API server ...")

		registerRoutes()

		go func() {
			Component.LogInfof("You can now access the API using: http://%s", ParamsRestAPI.BindAddress)
			if err := deps.Echo.Start(ParamsRestAPI.BindAddress); err != nil && !errors.Is(err, http.ErrServerClosed) {
				Component.LogErrorfAndExit("Stopped REST-API server due to an error (%s)", err)
			}
		}()

		ctxRegister, cancelRegister := context.WithTimeout(ctx, 5*time.Second)

		advertisedAddress := ParamsRestAPI.BindAddress
		if ParamsRestAPI.AdvertiseAddress != "" {
			advertisedAddress = ParamsRestAPI.AdvertiseAddress
		}

		routeName := strings.Replace(APIRoute, "/api/", "", 1)
		if err := deps.NodeBridge.RegisterAPIRoute(ctxRegister, routeName, advertisedAddress, APIRoute); err != nil {
			Component.LogErrorfAndExit("Registering INX api route failed: %s", err)
		}
		cancelRegister()

		Component.LogInfo("Starting API server ... done")
		<-ctx.Done()
		Component.LogInfo("Stopping API ...")

		ctxUnregister, cancelUnregister := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancelUnregister()

		//nolint:contextcheck // false positive
		if err := deps.NodeBridge.UnregisterAPIRoute(ctxUnregister, routeName); err != nil {
			Component.LogWarnf("Unregistering INX api route failed: %s", err)
		}

		shutdownCtx, shutdownCtxCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCtxCancel()

		//nolint:contextcheck // false positive
		if err := deps.Echo.Shutdown(shutdownCtx); err != nil {
			Component.LogWarn(err)
		}

		Component.LogInfo("Stopping API ... done")
	}, daemon.PriorityStopBlockIssuerAPI); err != nil {
		Component.LogPanicf("failed to start worker: %s", err)
	}

	return nil
}

// loadEd25519PrivateKeysFromEnvironment loads ed25519 private keys from the given environment variable.
func loadEd25519PrivateKeysFromEnvironment(name string) ([]ed25519.PrivateKey, error) {
	keys, exists := os.LookupEnv(name)
	if !exists {
		return nil, ierrors.Errorf("environment variable '%s' not set", name)
	}

	if len(keys) == 0 {
		return nil, ierrors.Errorf("environment variable '%s' not set", name)
	}

	privateKeysSplitted := strings.Split(keys, ",")
	privateKeys := make([]ed25519.PrivateKey, len(privateKeysSplitted))
	for i, key := range privateKeysSplitted {
		privateKey, err := crypto.ParseEd25519PrivateKeyFromString(key)
		if err != nil {
			return nil, ierrors.Errorf("environment variable '%s' contains an invalid private key '%s'", name, key)

		}
		privateKeys[i] = privateKey
	}

	return privateKeys, nil
}
