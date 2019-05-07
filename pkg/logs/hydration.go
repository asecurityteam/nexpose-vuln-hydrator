package logs

// HydrationError occurs when there is an error fetching vulnerability
// deatails from Nexpose
type HydrationError struct {
	Message string `logevent:"message,default=hyrdration-failure"`
	Reason  string `logevent:"reason"`
}
