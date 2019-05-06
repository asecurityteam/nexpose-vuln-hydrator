package domain

import "time"

// Asset is the Asset information from Nexpose
type Asset struct {
	LastScanned time.Time
	ID          int64
	IP          string
	Hostname    string
}
