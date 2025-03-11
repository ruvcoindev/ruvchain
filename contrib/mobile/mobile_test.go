package mobile

import (
	"os"
	"testing"

	"github.com/gologme/log"
)

func TestStartRuvchain(t *testing.T) {
	logger := log.New(os.Stdout, "", 0)
	logger.EnableLevel("error")
	logger.EnableLevel("warn")
	logger.EnableLevel("info")

	ruv := &Ruvchain{
		logger: logger,
	}
	if err := ruv.StartAutoconfigure(); err != nil {
		t.Fatalf("Failed to start Ruvchain: %s", err)
	}
	t.Log("Address:", ruv.GetAddressString())
	t.Log("Subnet:", ruv.GetSubnetString())
	t.Log("Routing entries:", ruv.GetRoutingEntries())
	if err := ruv.Stop(); err != nil {
		t.Fatalf("Failed to stop Ruvchain: %s", err)
	}
}
