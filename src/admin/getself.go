package admin

import (
	"encoding/hex"

	"github.com/ruvcoindev/ruvchain/src/version"
)

type GetSelfRequest struct{}

type GetSelfResponse struct {
	BuildName      string `json:"build_name"`
	BuildVersion   string `json:"build_version"`
	PublicKey      string `json:"key"`
	IPAddress      string `json:"address"`
	RoutingEntries uint64 `json:"routing_entries"`
	Subnet         string `json:"subnet"`
}

func (a *AdminSocket) getSelfHandler(_ *GetSelfRequest, res *GetSelfResponse) error {
	self := a.core.GetSelf()
	snet := a.core.Subnet()
	res.BuildName = version.BuildName()
	res.BuildVersion = version.BuildVersion()
	res.PublicKey = hex.EncodeToString(self.Key[:])
	res.IPAddress = a.core.Address().String()
	res.Subnet = snet.String()
	res.RoutingEntries = self.RoutingEntries
	return nil
}
