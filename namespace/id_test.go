package namespace

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestID_HexString(t *testing.T) {
	nID := ID("12345678")
	require.Equal(t, "3132333435363738", nID.HexString())
}
