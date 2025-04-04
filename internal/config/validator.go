func (c *Config) ValidateDNS() error {
	if c.DNS.Enabled {
		if len(c.DNS.Resolvers) == 0 {
			return errors.New("DNS requires at least one resolver")
		}
		
		if c.DNS.Pricing.BasePrice <= 0 {
			return errors.New("base price must be positive")
		}
	}
	return nil
}

func (c *Config) ValidateBlockchain() error {
	switch c.Blockchain.Consensus {
	case "poa":
		if len(c.Blockchain.ConsensusParams.Poa.Validators) == 0 {
			return errors.New("poa requires validators list")
		}
	case "dpos":
		if c.Blockchain.ConsensusParams.Dpos.DelegateCount < 10 {
			return errors.New("minimum 10 delegates for dpos")
		}
	}
	return nil
}
