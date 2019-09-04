package v1

//go:generate mockgen -destination mock_logger_test.go -package v1 github.com/asecurityteam/nexpose-vuln-hydrator/pkg/domain Logger
//go:generate mockgen -destination mock_hydrator_test.go -package v1 github.com/asecurityteam/nexpose-vuln-hydrator/pkg/domain Hydrator
//go:generate mockgen -destination mock_producer_test.go -package v1 github.com/asecurityteam/nexpose-vuln-hydrator/pkg/domain Producer
