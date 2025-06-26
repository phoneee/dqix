package cli

import (
	"fmt"
	"os"

	"github.com/dqix-org/dqix/internal/core"
	"github.com/dqix-org/dqix/internal/output"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	verbose    bool
	outputFormat string
	configFile string
)

var rootCmd = &cobra.Command{
	Use:   "dqix [domain]",
	Short: "Domain Quality Index - Go Implementation",
	Long: `DQIX (Domain Quality Index) is a multi-language tool for measuring 
domain security, performance, and compliance.

This is the Go implementation, designed for high performance and concurrent processing.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		domain := args[0]
		
		color.Cyan("🔍 DQIX - Domain Quality Assessment (Go)")
		color.Cyan("=" + fmt.Sprintf("%40s", ""))
		
		assessor := core.NewAssessor()
		if configFile != "" {
			if err := assessor.LoadConfig(configFile); err != nil {
				return fmt.Errorf("failed to load config: %w", err)
			}
		}
		
		result, err := assessor.Assess(domain)
		if err != nil {
			return fmt.Errorf("assessment failed: %w", err)
		}
		
		formatter := output.NewFormatter(outputFormat)
		return formatter.Output(result)
	},
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show version information",
	Run: func(cmd *cobra.Command, args []string) {
		color.Green("DQIX Go Implementation")
		color.White("Version: 1.2.0")
		color.White("Language: Go")
		color.White("Architecture: Multi-language")
	},
}

var benchmarkCmd = &cobra.Command{
	Use:   "benchmark [domains...]",
	Short: "Run performance benchmarks",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		color.Yellow("🚀 Running Go Performance Benchmark")
		
		assessor := core.NewAssessor()
		return assessor.Benchmark(args)
	},
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")
	rootCmd.PersistentFlags().StringVarP(&outputFormat, "output", "o", "json", "output format (json, csv, report)")
	rootCmd.PersistentFlags().StringVarP(&configFile, "config", "c", "", "config file path")
	
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(benchmarkCmd)
} 