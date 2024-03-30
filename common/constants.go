package common

const (
	LenOfValidators                = 512
	QuarterLenOfValidators         = LenOfValidators / 4
	LenOfPubKey                    = 48
	LenOfOnePubkeySSZBytes         = 64
	LenOfTotalValidatorsSSZBytes   = LenOfOnePubkeySSZBytes * LenOfValidators
	LenOfQuarterValidatorsSSZBytes = LenOfTotalValidatorsSSZBytes / 4
	LenOfAggregationBytes          = LenOfValidators / 8
	LenOfAggregationU64            = LenOfAggregationBytes / 8
	LenOfHash                      = 32
	LenOfSignature                 = 96
	FinalizedHeaderDepth           = 6
	FinalizedHeaderIndex           = 41 //TODO
	CurrentSyncCommitteeDepth      = 5
	CurrentSynCommitteeIndex       = 22
	NextSyncCommitteeDepth         = 5
	NextSyncCommitteeIndex         = 23
	ExecutionBranchDepth           = 5
	ExecutionBranchIndex           = 24
	ParentRootDepth                = 3
	ParentRootIndex                = 2 //
	StateRootDepth                 = 3
	StateRootIndex                 = 3 // bottom layer index
	FingerPrintElements            = 2
	FingerBitsPerElements          = 128
	SyncCommitteeRootElements      = 2
	SCRootBitsPerElements          = 128
)
