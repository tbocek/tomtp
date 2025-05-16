package tomtp

import "errors"

type RTT struct {
	srtt   uint64 // Smoothed RTT
	rttvar uint64 // RTT variation
}

func (c *Connection) rtoMicros() uint64 {
	// Standard formula from RFC 6298
	rto := c.srtt + 4*c.rttvar

	//the first packet
	if rto == 0 {
		return 200 * 1000 //with backoff, max 6.2 sec
	} else if rto < 100*1000 {
		return 100 * 1000 //do not go below 100ms
	} else if rto > 2*1000*1000 {
		return 2 * 1000 * 1000 //everything is reachable via 2sec
	}

	return rto
}

func (c *Connection) UpdateRTT(rttMeasurementMicros uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.srtt == 0 {
		// First measurement
		c.srtt = rttMeasurementMicros
		c.rttvar = rttMeasurementMicros / 2
	} else {
		// Calculate absolute difference for RTT variation
		var delta uint64
		if rttMeasurementMicros > c.srtt {
			delta = rttMeasurementMicros - c.srtt
		} else {
			delta = c.srtt - rttMeasurementMicros
		}

		// Integer-based RTT variation update using exact fractions
		// RTTVAR = 3/4 * RTTVAR + 1/4 * |SRTT-R'|
		c.rttvar = (c.rttvar*3)/4 + (delta*1)/4

		// Integer-based smoothed RTT update
		// SRTT = 7/8 * SRTT + 1/8 * R'
		c.srtt = (c.srtt*7)/8 + (rttMeasurementMicros*1)/8
	}
}

// -> 200000 / 400000 / 800000 / 1600000 / 3200000
func backoff(rtoMicros uint64, rtoNr int) (uint64, error) {
	if rtoNr <= 0 {
		return 0, errors.New("backoff requires a positive rto number")
	}
	if rtoNr > 5 {
		return 0, errors.New("max retry attempts (4) exceeded")
	}

	for i := 1; i < rtoNr; i++ {
		rtoMicros = rtoMicros * 2
	}

	return rtoMicros, nil
}
