package tomtp

import (
	"math"
)

type BBRState int

const (
	BBRStateStartup BBRState = iota
	BBRStateNormal
)

type BBR struct {
	// Core state
	state                       BBRState // Current state (Startup or Normal)
	cwnd                        uint64   // Congestion window (bytes)
	rttMin                      uint64   // Current minimum RTT estimate
	rttMinDecayFactorPct        uint64   // How quickly old minimums fade (smaller = more aggressive)
	bwMax                       uint64   // Current maximum bandwidth estimate
	bwMaxDecayFactorPct         uint64   // How quickly old maximums fade (smaller = more aggressive)
	bwInc                       uint64
	bwDec                       uint64
	dupAckCount                 int
	lastBBRStateStartupCwndTime uint64
}

// NewBBR creates a new BBR instance with default values
func NewBBR() BBR {
	return BBR{
		state:                BBRStateStartup,
		cwnd:                 10 * startMtu, // Start with 10 packets
		rttMin:               math.MaxUint64,
		rttMinDecayFactorPct: 95, // More aggressive: 0.9, Less aggressive: 0.99
		bwMax:                0,
		bwMaxDecayFactorPct:  95, // More aggressive: 0.9, Less aggressive: 0.99
	}
}

func (c *Connection) UpdateBBR(rttMeasurement uint64, bytesAcked uint64, nowMicros uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// 1. Update min RTT measurements
	if c.rttMin == math.MaxUint64 {
		c.rttMin = rttMeasurement
	} else {
		// Decay the minimum (allows it to rise if network conditions change)
		c.rttMin = (c.rttMin * 100) / c.rttMinDecayFactorPct
	}
	if rttMeasurement > 0 && rttMeasurement < c.rttMin*10 { // Ignore values more than 10x the min
		if rttMeasurement < c.rttMin { //this includes the decay -> more aggressive
			c.rttMin = rttMeasurement
		}
	}

	// 2. Update bandwidth estimate
	if c.bwMax > 0 {
		// Decay max bandwidth estimate
		c.bwMax = (c.bwMax * 100) / c.bwMaxDecayFactorPct
	}
	if rttMeasurement > 0 && bytesAcked > 0 {
		instantBw := bytesAcked * 1000000 / rttMeasurement
		if instantBw < c.bwMax*5 || c.bwMax == 0 { // Ignore suspiciously high bandwidth samples
			if instantBw > c.bwMax { //this includes the decay -> more aggressive
				c.bwMax = instantBw
				c.bwInc++
				c.bwDec = 0
			} else {
				c.bwInc = 0
				c.bwDec++
			}
		}
	}

	// 3. State-specific behavior
	switch c.BBR.state {
	case BBRStateStartup:
		if nowMicros-c.lastBBRStateStartupCwndTime > c.RTT.srtt {
			c.cwnd *= 2
			c.lastBBRStateStartupCwndTime = nowMicros
		}

		// Only exit startup on packet loss or significant RTT increase
		if c.bwDec >= 3 || (c.RTT.srtt/c.rttMin >= 2) {
			c.BBR.state = BBRStateNormal //if the bandwidth did not increase for the 3rd time, slow start is over the next time
		}
	case BBRStateNormal:
		// Handle probing in normal state

		// In Normal state: BDP-based cwnd with gain factor
		if c.bwMax > 0 && c.rttMin != math.MaxUint64 {
			// Calculate Bandwidth-Delay Product (BDP)
			bdp := (c.bwMax * c.rttMin) / 1000000
			rttRatioPct := (c.RTT.srtt * 100) / c.rttMin

			cwndGainPct := uint64(150) //keep the BDP at 1.5x for stable conditions

			// Adjust based on RTT inflation
			if rttRatioPct > 120 {
				// RTT is inflated, reduce gain to prevent queue buildup
				// Linear reduction: 1.5x at 120% RTT down to 1.0x at 200% RTT
				if rttRatioPct >= 200 {
					// Hard cap at 1.0x BDP when RTT doubles
					cwndGainPct = 100
				} else {
					// Linear interpolation between 150% and 100%
					// As rttRatioPct goes from 120 to 200, cwndGainPct goes from 150 to 100
					reduction := (50 * (rttRatioPct - 120)) / 80
					cwndGainPct = 150 - reduction
				}
			}

			// Adjust based on bandwidth trends
			if c.bwInc > 0 {
				cwndGainPct += 10 * minUint64(c.bwInc, 5)
			} else if c.bwDec > 0 {
				cwndGainPct -= 5 * minUint64(c.bwDec, 10)
			}

			cwndGainPct = minUint64(maxUint64(cwndGainPct, 75), 200)
			targetCwnd := (bdp * cwndGainPct) / 100

			minCwnd := 4 * c.mtu
			if targetCwnd < minCwnd {
				c.cwnd = minCwnd
			} else {
				c.cwnd = targetCwnd
			}
		}
	}
}

func (c *Connection) OnDuplicateAck() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.dupAckCount++
	if c.dupAckCount >= 3 {
		c.dupAckCount = 0

		c.BBR.bwMax = c.BBR.bwMax * 97 / 100 // Reduce by 3%
		c.BBR.cwnd = c.BBR.cwnd * 85 / 100   // Reduce by 15%
		minCwnd := 2 * c.mtu
		if c.BBR.cwnd < minCwnd {
			c.BBR.cwnd = minCwnd
		}
		c.BBR.state = BBRStateNormal
	}
}

func (c *Connection) OnPacketLoss() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.BBR.bwMax = c.BBR.bwMax * 95 / 100 // Reduce by 5%
	c.BBR.cwnd = c.BBR.cwnd * 75 / 100   // Reduce by 25%
	minCwnd := 2 * c.mtu
	if c.BBR.cwnd < minCwnd {
		c.BBR.cwnd = minCwnd
	}
	c.BBR.state = BBRStateNormal
}
