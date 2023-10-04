package blockissuer

import (
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/labstack/echo/v4"

	"github.com/iotaledger/hive.go/ierrors"
	"github.com/iotaledger/hive.go/serializer/v2/serix"
	"github.com/iotaledger/inx-app/pkg/httpserver"
	inx "github.com/iotaledger/inx/go"
	iotago "github.com/iotaledger/iota.go/v4"
	"github.com/iotaledger/iota.go/v4/blockissuer/pow"
	"github.com/iotaledger/iota.go/v4/builder"
	"github.com/iotaledger/iota.go/v4/nodeclient/apimodels"
)

const (
	HeaderBlockIssuerProofOfWorkNonce = "X-IOTA-BlockIssuer-PoW-Nonce"
	HeaderBlockIssuerCommitmentID     = "X-IOTA-BlockIssuer-Commitment-ID"
)

func registerRoutes() {
	deps.Echo.GET("/info", getInfo)
	deps.Echo.POST("/issue", sendPayload)
}

func getInfo(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]string{
		"blockIssuerAddress":     ParamsBlockIssuer.AccountAddress,
		"powTargetTrailingZeros": fmt.Sprintf("%d", ParamsBlockIssuer.ProofOfWork.TargetTrailingZeros),
	})
}

func proofOfWorkScore(data []byte, nonce uint64) int {
	// compute the digest
	h := pow.Hash.New()
	h.Write(data)
	powDigest := h.Sum(nil)

	return pow.TrailingZeros(powDigest[:], nonce)
}

func getRequestPoWNonce(c echo.Context) (uint64, error) {
	powNonce := c.Request().Header.Get(HeaderBlockIssuerProofOfWorkNonce)
	if powNonce == "" {
		return 0, ierrors.Wrapf(httpserver.ErrInvalidParameter, "invalid payload, proof of work nonce missing in the header %s", HeaderBlockIssuerProofOfWorkNonce)
	}

	var err error
	nonceValue, err := strconv.ParseUint(powNonce, 10, 64)
	if err != nil {
		return 0, ierrors.Wrapf(httpserver.ErrInvalidParameter, "invalid payload, invalid proof of work nonce value. error: %w", err)
	}

	return nonceValue, nil
}

func getRequestCommitmentID(c echo.Context) (iotago.CommitmentID, error) {
	commitmentIDHex := c.Request().Header.Get(HeaderBlockIssuerCommitmentID)
	if commitmentIDHex == "" {
		return iotago.EmptyCommitmentID, ierrors.Wrapf(httpserver.ErrInvalidParameter, "invalid payload, commitment ID is missing in the header %s", HeaderBlockIssuerCommitmentID)
	}

	commitmentID, err := iotago.SlotIdentifierFromHexString(commitmentIDHex)
	if err != nil {
		return iotago.EmptyCommitmentID, ierrors.Wrapf(httpserver.ErrInvalidParameter, "invalid payload, invalid proof of work nonce value. error: %w", err)
	}

	return commitmentID, nil
}

func getPayload(c echo.Context, requiresProofOfWork bool) (iotago.BlockPayload, []byte, error) {

	mimeType, err := httpserver.GetRequestContentType(c, httpserver.MIMEApplicationVendorIOTASerializerV2, echo.MIMEApplicationJSON)
	if err != nil {
		return nil, nil, ierrors.Wrapf(httpserver.ErrInvalidParameter, "invalid payload, error: %w", err)
	}

	var iotaPayload iotago.Payload

	if c.Request().Body == nil {
		// bad request
		return nil, nil, ierrors.Wrap(httpserver.ErrInvalidParameter, "invalid payload, error: request body missing")
	}

	bytes, err := io.ReadAll(c.Request().Body)
	if err != nil {
		return nil, nil, ierrors.Wrapf(httpserver.ErrInvalidParameter, "invalid payload, error: %w", err)
	}

	// Check if we got a JSON payload or a binary payload
	var payloadBytes []byte
	switch mimeType {
	case echo.MIMEApplicationJSON:
		if err := deps.NodeBridge.APIProvider().CurrentAPI().JSONDecode(bytes, iotaPayload, serix.WithValidation()); err != nil {
			return nil, nil, ierrors.Wrapf(httpserver.ErrInvalidParameter, "invalid payload, error: %w", err)
		}

		if requiresProofOfWork {
			// Serialize the payload so that we can verify the PoW
			payloadBytes, err = deps.NodeBridge.APIProvider().CurrentAPI().Encode(iotaPayload)
			if err != nil {
				return nil, nil, ierrors.Wrapf(httpserver.ErrInvalidParameter, "invalid payload, error: %w", err)
			}
		}

	case httpserver.MIMEApplicationVendorIOTASerializerV2:
		if _, err := deps.NodeBridge.APIProvider().CurrentAPI().Decode(bytes, iotaPayload, serix.WithValidation()); err != nil {
			return nil, nil, ierrors.Wrapf(httpserver.ErrInvalidParameter, "invalid payload, error: %w", err)
		}
		// No need to encode the payload again, we already have the bytes
		payloadBytes = bytes

	default:
		return nil, nil, echo.ErrUnsupportedMediaType
	}

	return iotaPayload, payloadBytes, nil
}

func getAllotedMana(signedTx *iotago.SignedTransaction) (iotago.Mana, error) {
	// Check if the transaction is allotting mana to the issuer
	var allotedMana iotago.Mana
	for _, allotment := range signedTx.Transaction.Allotments {
		if allotment.AccountID == deps.AccountAddress.AccountID() {
			allotedMana = allotment.Value
			break
		}
	}

	// Check if the transaction is allotting mana to the issuer
	if allotedMana == 0 {
		return 0, ierrors.Wrap(httpserver.ErrInvalidParameter, "invalid payload, transaction is not allotting any mana")
	}

	return allotedMana, nil
}

// validatePayload validates the payload via INX to see if the transaction as constructed would be accepted.
func validatePayload(c echo.Context, signedTx *iotago.SignedTransaction) error {
	wrappedPayload, err := inx.WrapPayload(signedTx, signedTx.API)
	if err != nil {
		return ierrors.Wrapf(httpserver.ErrInvalidParameter, "failed to wrap payload: %w", err)
	}

	if response, err := deps.NodeBridge.Client().ValidatePayload(c.Request().Context(), wrappedPayload); err != nil {
		return ierrors.Wrapf(httpserver.ErrInvalidParameter, "failed to execute Stardust VM: %w", err)
	} else if !response.GetIsValid() {
		return ierrors.Wrapf(httpserver.ErrInvalidParameter, "failed to execute Stardust VM: %s", response.GetError())
	}

	return nil
}

func constructBlock(c echo.Context, signedTx *iotago.SignedTransaction, allotedMana iotago.Mana, commitmentID iotago.CommitmentID) (*iotago.ProtocolBlock, error) {
	// Request tips
	strong, weak, shallowLike, err := deps.NodeBridge.RequestTips(c.Request().Context(), iotago.BlockMaxParents)
	if err != nil {
		return nil, ierrors.Wrapf(echo.ErrInternalServerError, "failed to request tips: %w", err)
	}

	// Construct Block
	blockBuilder := builder.NewBasicBlockBuilder(deps.NodeBridge.APIProvider().CurrentAPI())

	// we need to set the commitmentID to the one the payload signer used, otherwise the RMC could be different,
	// and therefore the allotment could be wrong, which causes the block to fail.
	blockBuilder.SlotCommitmentID(commitmentID)
	blockBuilder.LatestFinalizedSlot(deps.NodeBridge.LatestFinalizedCommitmentID().Slot())
	blockBuilder.StrongParents(strong)
	blockBuilder.WeakParents(weak)
	blockBuilder.ShallowLikeParents(shallowLike)
	blockBuilder.Payload(signedTx)
	// set the max burned mana to the mana that was alloted to the block issuer.
	// if the value would be too low, the block would be filtered by the node of the block issuer.
	blockBuilder.MaxBurnedMana(allotedMana)
	blockBuilder.Sign(deps.AccountAddress.AccountID(), deps.PrivateKey)

	iotaBlock, err := blockBuilder.Build()
	if err != nil {
		return nil, ierrors.Wrapf(httpserver.ErrInvalidParameter, "failed to build block: %w", err)
	}

	return iotaBlock, nil
}

func sendPayload(c echo.Context) error {
	commitmentID, err := getRequestCommitmentID(c)
	if err != nil {
		return err
	}

	requiresProofOfWork := ParamsBlockIssuer.ProofOfWork.TargetTrailingZeros > 0

	var nonceValue uint64
	if requiresProofOfWork {
		nonceValue, err = getRequestPoWNonce(c)
		if err != nil {
			return err
		}
	}

	iotaPayload, payloadBytes, err := getPayload(c, requiresProofOfWork)
	if err != nil {
		return err
	}

	// Check for correct PoW
	if requiresProofOfWork {
		if trailingZerosCount := proofOfWorkScore(payloadBytes, nonceValue); trailingZerosCount < ParamsBlockIssuer.ProofOfWork.TargetTrailingZeros {
			return ierrors.Wrapf(httpserver.ErrInvalidParameter, "invalid payload, proof of work failed, required %d trailing zeros, got %d", ParamsBlockIssuer.ProofOfWork.TargetTrailingZeros, trailingZerosCount)
		}
	}

	// Check for a signed transaction
	signedTx, ok := iotaPayload.(*iotago.SignedTransaction)
	if !ok {
		return ierrors.Wrapf(httpserver.ErrInvalidParameter, "invalid payload, only transactions are supported")
	}

	allotedMana, err := getAllotedMana(signedTx)
	if err != nil {
		return err
	}

	if err := validatePayload(c, signedTx); err != nil {
		return err
	}

	iotaBlock, err := constructBlock(c, signedTx, allotedMana, commitmentID)
	if err != nil {
		return err
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
