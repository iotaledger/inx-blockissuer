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

func (s *BlockIssuerServer) configureRoutes(echoGroup *echo.Group) {
	echoGroup.GET(api.BlockIssuerEndpointInfo, s.getInfo)
	echoGroup.POST(api.BlockIssuerEndpointIssuePayload, s.sendPayload)
}

func (s *BlockIssuerServer) getInfo(c echo.Context) error {
	return httpserver.SendResponseByHeader(c, s.nodeBridge.APIProvider().CommittedAPI(), &api.BlockIssuerInfo{
		BlockIssuerAddress:     s.accountAddress.Bech32(s.hrp),
		PowTargetTrailingZeros: s.powTargetTrailingZeros,
	})
}

func (s *BlockIssuerServer) proofOfWorkTrailingZeroes(data []byte, nonce uint64) int {
	// compute the digest
	h := pow.Hash.New()
	h.Write(data)
	powDigest := h.Sum(nil)

	return pow.TrailingZeros(powDigest[:], nonce)
}

func (s *BlockIssuerServer) getRequestPoWNonce(c echo.Context) (uint64, error) {
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

func (s *BlockIssuerServer) getRequestCommitmentID(c echo.Context) (iotago.CommitmentID, error) {
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

func (s *BlockIssuerServer) getPayload(c echo.Context, requiresProofOfWork bool) (iotago.ApplicationPayload, []byte, error) {
	var payloadBytes []byte
	iotaPayload, err := httpserver.ParseRequestByHeader(c, s.nodeBridge.APIProvider().CommittedAPI(), func(bytes []byte) (iotago.ApplicationPayload, int, error) {
		var iotaPayload iotago.ApplicationPayload
		consumed, err := s.nodeBridge.APIProvider().CommittedAPI().Decode(bytes, &iotaPayload, serix.WithValidation())
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
		payloadBytes, err = s.nodeBridge.APIProvider().CommittedAPI().Encode(iotaPayload)
		if err != nil {
			return nil, nil, ierrors.Wrapf(httpserver.ErrInvalidParameter, "invalid payload, error: %w", err)
		}
	}

	return iotaPayload, payloadBytes, nil
}

func (s *BlockIssuerServer) getAllotedMana(signedTx *iotago.SignedTransaction) (iotago.Mana, error) {
	// Check if the transaction is allotting mana to the issuer
	var allotedMana iotago.Mana
	for _, allotment := range signedTx.Transaction.Allotments {
		if allotment.AccountID.Matches(s.accountAddress.AccountID()) {
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
func (s *BlockIssuerServer) validatePayload(c echo.Context, signedTx *iotago.SignedTransaction) error {
	wrappedPayload, err := inx.WrapPayload(signedTx, signedTx.API)
	if err != nil {
		return ierrors.Wrapf(httpserver.ErrInvalidParameter, "failed to wrap payload: %w", err)
	}

	if response, err := s.nodeBridge.Client().ValidatePayload(c.Request().Context(), wrappedPayload); err != nil {
		return ierrors.Wrapf(httpserver.ErrInvalidParameter, "failed to execute VM: %w", err)
	} else if !response.GetIsValid() {
		return ierrors.Wrapf(httpserver.ErrInvalidParameter, "failed to execute VM: %s", response.GetError())
	}

	return nil
}

func (s *BlockIssuerServer) constructBlock(c echo.Context, signedTx *iotago.SignedTransaction, allotedMana iotago.Mana, commitmentID iotago.CommitmentID) (*iotago.Block, error) {
	// Request tips
	strong, weak, shallowLike, err := s.nodeBridge.RequestTips(c.Request().Context(), iotago.BasicBlockMaxParents)
	if err != nil {
		return nil, ierrors.Wrapf(echo.ErrInternalServerError, "failed to request tips: %w", err)
	}

	// Construct Block
	blockBuilder := builder.NewBasicBlockBuilder(s.nodeBridge.APIProvider().CommittedAPI())

	// we need to set the commitmentID to the one the payload signer used, otherwise the RMC could be different,
	// and therefore the allotment could be wrong, which causes the block to fail.
	blockBuilder.SlotCommitmentID(commitmentID)
	blockBuilder.LatestFinalizedSlot(s.nodeBridge.LatestFinalizedCommitment().Commitment.Slot)
	blockBuilder.StrongParents(strong)
	blockBuilder.WeakParents(weak)
	blockBuilder.ShallowLikeParents(shallowLike)
	blockBuilder.Payload(signedTx)
	// set the max burned mana to the mana that was alloted to the block issuer.
	// if the value would be too low, the block would be filtered by the node of the block issuer.
	blockBuilder.MaxBurnedMana(allotedMana)
	blockBuilder.Sign(s.accountAddress.AccountID(), s.privateKey)

	iotaBlock, err := blockBuilder.Build()
	if err != nil {
		return nil, ierrors.Wrapf(httpserver.ErrInvalidParameter, "failed to build block: %w", err)
	}

	return iotaBlock, nil
}

func (s *BlockIssuerServer) sendPayload(c echo.Context) error {
	// get the commitment ID from the request
	commitmentID, err := s.getRequestCommitmentID(c)
	if err != nil {
		return err
	}

	requiresProofOfWork := s.powTargetTrailingZeros > 0

	var nonceValue uint64
	if requiresProofOfWork {
		// get the PoW nonce from the request
		nonceValue, err = s.getRequestPoWNonce(c)
		if err != nil {
			return err
		}
	}

	// get the payload from the request
	iotaPayload, payloadBytes, err := s.getPayload(c, requiresProofOfWork)
	if err != nil {
		return err
	}

	// check for correct PoW
	if requiresProofOfWork {
		if trailingZerosCount := s.proofOfWorkTrailingZeroes(payloadBytes, nonceValue); uint8(trailingZerosCount) < s.powTargetTrailingZeros {
			return ierrors.Wrapf(httpserver.ErrInvalidParameter, "invalid payload, proof of work failed, required %d trailing zeros, got %d", s.powTargetTrailingZeros, trailingZerosCount)
		}
	}

	// check for a signed transaction
	signedTx, ok := iotaPayload.(*iotago.SignedTransaction)
	if !ok {
		return ierrors.Wrap(httpserver.ErrInvalidParameter, "invalid payload, only signed transactions are supported")
	}

	// get the mana that was alloted to the block issuer
	allotedMana, err := s.getAllotedMana(signedTx)
	if err != nil {
		return err
	}

	// validate the payload
	if err := s.validatePayload(c, signedTx); err != nil {
		return err
	}

	// construct the block and sign it
	iotaBlock, err := s.constructBlock(c, signedTx, allotedMana, commitmentID)
	if err != nil {
		return err
	}

	// submit Block to the node
	blockID, err := s.nodeBridge.SubmitBlock(c.Request().Context(), iotaBlock)
	if err != nil {
		return ierrors.Wrapf(httpserver.ErrInvalidParameter, "failed to attach block: %w", err)
	}

	// send the response
	return httpserver.SendResponseByHeader(c, s.nodeBridge.APIProvider().CommittedAPI(), &api.BlockCreatedResponse{BlockID: blockID})
}
