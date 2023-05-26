package namespace

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestID_HexString(t *testing.T) {
	nID := ID("12345678")
	require.Equal(t, "3132333435363738", nID.HexString())
}
