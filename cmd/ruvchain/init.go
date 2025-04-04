// cmd/ruvchain/init.go
func initCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use: "init",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := config.DefaultConfig()
			
			if name, _ := cmd.Flags().GetString("name"); name != "" {
				cfg.Node.Name = name
			}
			
			// ... аналогично для других параметров
			
			return cfg.Save("config.yaml")
		},
	}

	cmd.Flags().String("name", "", "Node name")
	cmd.Flags().String("consensus", "poa", "Consensus type")
	return cmd
}
