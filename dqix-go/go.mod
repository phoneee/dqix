module github.com/dqix-org/dqix

go 1.23

toolchain go1.23.4

require (
	// CLI and UI - Updated for Go 1.23+
	github.com/fatih/color v1.18.0

	// Networking and DNS - Latest versions
	github.com/miekg/dns v1.1.62
	github.com/schollz/progressbar/v3 v3.17.1
	github.com/spf13/cobra v1.8.1

	// Testing and benchmarking
	github.com/stretchr/testify v1.10.0 // indirect
	golang.org/x/net v0.33.0

	// Concurrency and performance
	golang.org/x/sync v0.10.0
	golang.org/x/time v0.8.0

	// Serialization and config
	gopkg.in/yaml.v3 v3.0.1
)

require (
	// Indirect dependencies - updated versions
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mitchellh/colorstring v0.0.0-20190213212951-d06e56a500db // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	golang.org/x/mod v0.22.0 // indirect
	golang.org/x/sys v0.28.0 // indirect
	golang.org/x/term v0.27.0
	golang.org/x/tools v0.28.0 // indirect
)

require golang.org/x/text v0.21.0 // indirect
