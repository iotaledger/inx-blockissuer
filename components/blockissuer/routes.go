package blockissuer

import (
	"io"
	"net/http"

	"github.com/labstack/echo/v4"

	"github.com/iotaledger/hive.go/ierrors"
	"github.com/iotaledger/inx-app/pkg/httpserver"
	iotago "github.com/iotaledger/iota.go/v4"
	"github.com/iotaledger/iota.go/v4/builder"
	"github.com/iotaledger/iota.go/v4/nodeclient/apimodels"
)

func registerRoutes() {
	deps.Echo.GET("/info", getInfo)
	deps.Echo.POST("/issue", sendPayload)
}

func getInfo(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]string{
		"issuer": ParamsBlockIssuer.AccountAddress,
	})
}

func sendPayload(c echo.Context) error {
	mimeType, err := httpserver.GetRequestContentType(c, httpserver.MIMEApplicationVendorIOTASerializerV2, echo.MIMEApplicationJSON)
	if err != nil {
		return ierrors.Wrapf(httpserver.ErrInvalidParameter, "invalid payload, error: %w", err)
	}

	var iotaPayload iotago.Payload

	if c.Request().Body == nil {
		// bad request
		return ierrors.Wrap(httpserver.ErrInvalidParameter, "invalid payload, error: request body missing")
	}

	bytes, err := io.ReadAll(c.Request().Body)
	if err != nil {
		return ierrors.Wrapf(httpserver.ErrInvalidParameter, "invalid payload, error: %w", err)
	}

	// Check if we got a JSON payload or a binary payload
	switch mimeType {
	case echo.MIMEApplicationJSON:
		if err := deps.NodeBridge.APIProvider().CurrentAPI().JSONDecode(bytes, iotaPayload); err != nil {
			return ierrors.Wrapf(httpserver.ErrInvalidParameter, "invalid payload, error: %w", err)
		}

	case httpserver.MIMEApplicationVendorIOTASerializerV2:
		if _, err := deps.NodeBridge.APIProvider().CurrentAPI().Decode(bytes, iotaPayload); err != nil {
			return ierrors.Wrapf(httpserver.ErrInvalidParameter, "invalid payload, error: %w", err)
		}

	default:
		return echo.ErrUnsupportedMediaType
	}

	// Check for a signed transaction
	signedTx, ok := iotaPayload.(*iotago.SignedTransaction)
	if !ok {
		return ierrors.Wrapf(httpserver.ErrInvalidParameter, "invalid payload, only transactions are supported")
	}

	// Check if the transaction is allotting mana to the issuer
	var allotedMana iotago.Mana
	for _, allotment := range signedTx.Transaction.Allotments {
		if allotment.AccountID == deps.AccountAddress.AccountID() {
			allotedMana = allotment.Value
			break
		}
	}

	if allotedMana == 0 {
		return ierrors.Wrap(httpserver.ErrInvalidParameter, "invalid payload, transaction is not allotting any mana")
	}

	// Request tips
	strong, weak, shallowLike, err := deps.NodeBridge.RequestTips(c.Request().Context(), iotago.BlockMaxParents)
	if err != nil {
		return ierrors.Wrapf(echo.ErrInternalServerError, "failed to request tips: %w", err)
	}

	// Construct Block
	blockBuilder := builder.NewBasicBlockBuilder(deps.NodeBridge.APIProvider().CurrentAPI())
	latestCommitment, err := deps.NodeBridge.LatestCommitment()
	if err != nil {
		return ierrors.Wrapf(echo.ErrInternalServerError, "failed to get latest commitment: %w", err)
	}
	blockBuilder.SlotCommitmentID(latestCommitment.MustID())
	blockBuilder.LatestFinalizedSlot(deps.NodeBridge.LatestFinalizedCommitmentID().Slot())
	blockBuilder.StrongParents(strong)
	blockBuilder.WeakParents(weak)
	blockBuilder.ShallowLikeParents(shallowLike)
	blockBuilder.Payload(signedTx)
	blockBuilder.MaxBurnedMana(allotedMana)
	blockBuilder.Sign(deps.AccountAddress.AccountID(), deps.PrivateKey)
	iotaBlock, err := blockBuilder.Build()
	if err != nil {
		return ierrors.Wrapf(httpserver.ErrInvalidParameter, "failed to build block: %w", err)
	}

	// Submit Block
	blockID, err := deps.NodeBridge.SubmitBlock(c.Request().Context(), iotaBlock)
	if err != nil {
		return ierrors.Wrapf(httpserver.ErrInvalidParameter, "failed to attach block: %w", err)
	}

	jsonResult, err := deps.NodeBridge.APIProvider().CurrentAPI().JSONEncode(&apimodels.BlockCreatedResponse{BlockID: blockID})
	if err != nil {
		return err
	}

	return c.JSONBlob(http.StatusOK, jsonResult)
}
