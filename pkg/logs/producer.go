package logs

// PayloadSizeLimitExceededError occurs when there is an error producing a vulnerability
// event due to the payload size exceeding the limit
type PayloadSizeLimitExceededError struct {
	Message  string `logevent:"message,default=payload-size-limit-exceeded"`
	Reason   string `logevent:"reason"`
	ScanTime string `logevent:"scanTime"`
	ID       int    `logevent:"id"`
	IP       string `logevent:"ip"`
	Hostname string `logevent:"hostname"`
}
