package blockissuer

import (
	"strconv"

	"github.com/labstack/echo/v4"

	"github.com/iotaledger/hive.go/ierrors"
	"github.com/iotaledger/hive.go/serializer/v2/serix"
	"github.com/iotaledger/inx-app/pkg/httpserver"
	inx "github.com/iotaledger/inx/go"
	iotago "github.com/iotaledger/iota.go/v4"
	"github.com/iotaledger/iota.go/v4/api"
	"github.com/iotaledger/iota.go/v4/blockissuer/pow"
	"github.com/iotaledger/iota.go/v4/builder"
)

const (
	HeaderBlockIssuerProofOfWorkNonce = "X-IOTA-BlockIssuer-PoW-Nonce"
	HeaderBlockIssuerCommitmentID     = "X-IOTA-BlockIssuer-Commitment-ID"
)

func registerRoutes() {
	echoGroup := deps.Echo.Group(APIRoute)
	echoGroup.GET(api.BlockIssuerEndpointInfo, getInfo)
	echoGroup.POST(api.BlockIssuerEndpointIssuePayload, sendPayload)
}

func getInfo(c echo.Context) error {
	return httpserver.SendResponseByHeader(c, deps.NodeBridge.APIProvider().CommittedAPI(), &api.BlockIssuerInfo{
		BlockIssuerAddress:     ParamsBlockIssuer.AccountAddress,
		PowTargetTrailingZeros: ParamsBlockIssuer.ProofOfWork.TargetTrailingZeros,
	})
}

func proofOfWorkTrailingZeroes(data []byte, nonce uint64) int {
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
		return 0, ierrors.Wrapf(httpserver.ErrInvalidParameter, "invalid payload, invalid proof of work nonce value in the header %s, error: %w", HeaderBlockIssuerProofOfWorkNonce, err)
	}

	return nonceValue, nil
}

func getRequestCommitmentID(c echo.Context) (iotago.CommitmentID, error) {
	commitmentIDHex := c.Request().Header.Get(HeaderBlockIssuerCommitmentID)
	if commitmentIDHex == "" {
		return iotago.EmptyCommitmentID, ierrors.Wrapf(httpserver.ErrInvalidParameter, "invalid payload, commitment ID is missing in the header %s", HeaderBlockIssuerCommitmentID)
	}

	commitmentID, err := iotago.CommitmentIDFromHexString(commitmentIDHex)
	if err != nil {
		return iotago.EmptyCommitmentID, ierrors.Wrapf(httpserver.ErrInvalidParameter, "invalid payload, invalid commitment ID value in the header %s, error: %w", HeaderBlockIssuerCommitmentID, err)
	}

	return commitmentID, nil
}

func getPayload(c echo.Context, requiresProofOfWork bool) (iotago.ApplicationPayload, []byte, error) {
	var payloadBytes []byte
	iotaPayload, err := httpserver.ParseRequestByHeader(c, deps.NodeBridge.APIProvider().CommittedAPI(), func(bytes []byte) (iotago.ApplicationPayload, int, error) {
		var iotaPayload iotago.ApplicationPayload
		consumed, err := deps.NodeBridge.APIProvider().CommittedAPI().Decode(bytes, &iotaPayload, serix.WithValidation())
		if err != nil {
			return nil, consumed, ierrors.Wrapf(httpserver.ErrInvalidParameter, "invalid payload, error: %w", err)
		}

		// No need to encode the payload again, we already have the bytes
		payloadBytes = bytes

		return iotaPayload, consumed, nil
	})
	if err != nil {
		return nil, nil, err
	}

	if requiresProofOfWork && len(payloadBytes) == 0 {
		// Serialize the payload so that we can verify the PoW
		payloadBytes, err = deps.NodeBridge.APIProvider().CommittedAPI().Encode(iotaPayload)
		if err != nil {
			return nil, nil, ierrors.Wrapf(httpserver.ErrInvalidParameter, "invalid payload, error: %w", err)
		}
	}

	return iotaPayload, payloadBytes, nil
}

func getAllotedMana(signedTx *iotago.SignedTransaction) (iotago.Mana, error) {
	// Check if the transaction is allotting mana to the issuer
	var allotedMana iotago.Mana
	for _, allotment := range signedTx.Transaction.Allotments {
		if allotment.AccountID.Matches(deps.AccountAddress.AccountID()) {
			allotedMana = allotment.Mana
			break
		}
	}

	// Check if the transaction is allotting mana to the issuer
	if allotedMana == 0 {
		return 0, ierrors.Wrap(httpserver.ErrInvalidParameter, "invalid payload, transaction is not allotting any mana to the block issuer account")
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
		return ierrors.Wrapf(httpserver.ErrInvalidParameter, "failed to execute VM: %w", err)
	} else if !response.GetIsValid() {
		return ierrors.Wrapf(httpserver.ErrInvalidParameter, "failed to execute VM: %s", response.GetError())
	}

	return nil
}

func constructBlock(c echo.Context, signedTx *iotago.SignedTransaction, allotedMana iotago.Mana, commitmentID iotago.CommitmentID) (*iotago.Block, error) {
	// Request tips
	strong, weak, shallowLike, err := deps.NodeBridge.RequestTips(c.Request().Context(), iotago.BasicBlockMaxParents)
	if err != nil {
		return nil, ierrors.Wrapf(echo.ErrInternalServerError, "failed to request tips: %w", err)
	}

	// Construct Block
	blockBuilder := builder.NewBasicBlockBuilder(deps.NodeBridge.APIProvider().CommittedAPI())

	// we need to set the commitmentID to the one the payload signer used, otherwise the RMC could be different,
	// and therefore the allotment could be wrong, which causes the block to fail.
	blockBuilder.SlotCommitmentID(commitmentID)
	blockBuilder.LatestFinalizedSlot(deps.NodeBridge.LatestFinalizedCommitment().Commitment.Slot)
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
	// get the commitment ID from the request
	commitmentID, err := getRequestCommitmentID(c)
	if err != nil {
		return err
	}

	requiresProofOfWork := ParamsBlockIssuer.ProofOfWork.TargetTrailingZeros > 0

	var nonceValue uint64
	if requiresProofOfWork {
		// get the PoW nonce from the request
		nonceValue, err = getRequestPoWNonce(c)
		if err != nil {
			return err
		}
	}

	// get the payload from the request
	iotaPayload, payloadBytes, err := getPayload(c, requiresProofOfWork)
	if err != nil {
		return err
	}

	// check for correct PoW
	if requiresProofOfWork {
		if trailingZerosCount := proofOfWorkTrailingZeroes(payloadBytes, nonceValue); uint8(trailingZerosCount) < ParamsBlockIssuer.ProofOfWork.TargetTrailingZeros {
			return ierrors.Wrapf(httpserver.ErrInvalidParameter, "invalid payload, proof of work failed, required %d trailing zeros, got %d", ParamsBlockIssuer.ProofOfWork.TargetTrailingZeros, trailingZerosCount)
		}
	}

	// check for a signed transaction
	signedTx, ok := iotaPayload.(*iotago.SignedTransaction)
	if !ok {
		return ierrors.Wrap(httpserver.ErrInvalidParameter, "invalid payload, only signed transactions are supported")
	}

	// get the mana that was alloted to the block issuer
	allotedMana, err := getAllotedMana(signedTx)
	if err != nil {
		return err
	}

	// validate the payload
	if err := validatePayload(c, signedTx); err != nil {
		return err
	}

	// construct the block and sign it
	iotaBlock, err := constructBlock(c, signedTx, allotedMana, commitmentID)
	if err != nil {
		return err
	}

	// submit Block to the node
	blockID, err := deps.NodeBridge.SubmitBlock(c.Request().Context(), iotaBlock)
	if err != nil {
		return ierrors.Wrapf(httpserver.ErrInvalidParameter, "failed to attach block: %w", err)
	}

	// send the response
	return httpserver.SendResponseByHeader(c, deps.NodeBridge.APIProvider().CommittedAPI(), &api.BlockCreatedResponse{BlockID: blockID})
}
