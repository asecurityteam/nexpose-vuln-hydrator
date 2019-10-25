package dependencycheck

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

// DependencyCheck implements the interfaces to fetch vulnerabilities and solutions from nexpose
type DependencyCheck struct {
	HTTPClient  *http.Client
	NexposeHost *url.URL
}

// DepCheck fetches the solutions to a particular vulnerability
func (dc *DependencyCheck) DepCheck(ctx context.Context) error {
	u, _ := url.Parse(dc.NexposeHost.String() + "/api/3/solutions/mysql-upgrade-latest")
	req, _ := http.NewRequest(http.MethodGet, u.String(), http.NoBody)
	res, err := dc.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		// Nexpose is down?  Nexpose unexpectedly gave 404?
		headers, errMarshal := json.Marshal(res.Header)
		if errMarshal != nil {
			headers = []byte("(could not marshal response headers)")
		}
		return fmt.Errorf("Nexpose unexpectedly returned non-200 response code: %d attempting to GET: %s.  Response headers: %s", res.StatusCode, u.String(), string(headers))
	}

	return nil
}
