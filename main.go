package tomtp

import (
	"github.com/MatusOllah/slogcolor"
	"github.com/fatih/color"
	"log/slog"
	"os"
)

const (
	//maxConnections = 1000
	maxBuffer     = 9000 //support large packets
	maxRingBuffer = 100
	startMtu      = 1400
	//
	alpha  = 0.125 // Factor for SRTT
	beta   = 0.25  // Factor for RTTVAR
	k      = 4     // Multiplier for RTTVAR in the PTO calculation
	minPto = 1     // Timer granularity
)

var (
	logger = slog.New(slogcolor.NewHandler(os.Stderr, &slogcolor.Options{
		Level:         slog.LevelDebug,
		TimeFormat:    "15:04:05.000",
		SrcFileMode:   slogcolor.ShortFile,
		SrcFileLength: 16,
		MsgPrefix:     color.HiWhiteString("|"),
		MsgColor:      color.New(color.FgHiWhite),
		MsgLength:     16,
	}))
)

func init() {
	color.NoColor = false
	slog.SetDefault(logger)
}
