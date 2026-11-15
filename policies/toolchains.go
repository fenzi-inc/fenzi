package policies

import (
	"os"
	"strings"
)

// Toolchain is what a project's language needs inside the sandbox: the
// commands the agent runs to build and test it, and the Debian packages that
// add them to an agent image that lacks them. The agent images are
// node:22-bookworm-slim with git and python3, so node and python need no
// packages; the rest are added to a copy of the agent's image, on this
// machine, only for a project whose files call for them.
//
// The packages were installed on fenzi/claude:2.1.288 (arm64) on 25 October
// 2026, and each command answered as the image's sandbox user: PHP 8.2.35
// with Composer 2.5.5, Ruby 3.1.2 with Bundler 2.3.15, OpenJDK 17.0.21,
// Maven 3.8.7, and Go 1.23.5 from bookworm-backports. Bookworm's own Go is
// 1.19, which reads no toolchain line in go.mod; from 1.21 on, go fetches the
// version go.mod asks for from proxy.golang.org, which the go stack opens.
type Toolchain struct {
	Name string
	// Files select the toolchain, as Stack.Files do.
	Files []string
	// Commands must be on the sandbox's PATH for the agent to build and test
	// the project.
	Commands []string
	// Packages come from bookworm, Backports from bookworm-backports. Both
	// are empty when the agent images carry the commands already, and when
	// Debian has no version recent enough to be worth adding.
	Packages  []string
	Backports []string
	// Missing says, for a toolchain Fenzi does not add, why not; it is shown
	// to the person and told to the agent when the commands are not there.
	Missing string
}

var toolchains = []Toolchain{
	{Name: "node", Files: []string{"package.json"}, Commands: []string{"node", "npm"}},
	{Name: "python", Files: []string{"pyproject.toml", "requirements.txt", "setup.py", "Pipfile"}, Commands: []string{"python3", "pip3"}},
	// The extensions Symfony and Laravel ask for beyond php-cli's own, and
	// unzip, which Composer uses for package archives.
	{Name: "php", Files: []string{"composer.json"}, Commands: []string{"php", "composer"},
		Packages: []string{"php-cli", "composer", "php-xml", "php-mbstring", "php-curl", "php-zip", "php-intl", "php-sqlite3", "unzip"}},
	{Name: "ruby", Files: []string{"Gemfile"}, Commands: []string{"ruby", "bundle"}, Packages: []string{"ruby-full", "ruby-bundler"}},
	{Name: "java", Files: []string{"pom.xml", "build.gradle", "build.gradle.kts"}, Commands: []string{"java"}, Packages: []string{"openjdk-17-jdk-headless"}},
	{Name: "maven", Files: []string{"pom.xml"}, Commands: []string{"mvn"}, Packages: []string{"maven"}},
	{Name: "go", Files: []string{"go.mod"}, Commands: []string{"go"}, Backports: []string{"golang-go"}},
	// Bookworm's Rust is 1.63, older than most crates accept.
	{Name: "rust", Files: []string{"Cargo.toml"}, Commands: []string{"cargo", "rustc"},
		Missing: "Fenzi does not add Rust yet: Debian's is 1.63, older than most crates accept"},
	{Name: "dotnet", Files: []string{"*.csproj", "*.fsproj", "*.sln"}, Commands: []string{"dotnet"},
		Missing: "Fenzi does not add .NET yet: Debian does not package it"},
}

// Toolchains returns every toolchain, in a fixed order.
func Toolchains() []Toolchain {
	out := make([]Toolchain, len(toolchains))
	for i, t := range toolchains {
		t.Files = append([]string(nil), t.Files...)
		t.Commands = append([]string(nil), t.Commands...)
		t.Packages = append([]string(nil), t.Packages...)
		t.Backports = append([]string(nil), t.Backports...)
		out[i] = t
	}
	return out
}

// Adds reports whether Fenzi adds the toolchain to the agent's image.
func (t Toolchain) Adds() bool { return len(t.Packages)+len(t.Backports) > 0 }

// DetectToolchains returns the toolchains whose files are in dir or in a
// folder one level down, in the order of Toolchains. Like DetectStacks, it
// never reads the home folder.
func DetectToolchains(dir string) []Toolchain {
	home, _ := os.UserHomeDir()
	return detectToolchains(dir, home)
}

func detectToolchains(dir, home string) []Toolchain {
	names := folderFiles(dir, home)
	var out []Toolchain
	for _, t := range Toolchains() {
		if matchFiles(t.Files, names) {
			out = append(out, t)
		}
	}
	return out
}

// ToolchainNames is how messages name the toolchains: "php, go".
func ToolchainNames(list []Toolchain) string {
	names := make([]string, len(list))
	for i, t := range list {
		names[i] = t.Name
	}
	return strings.Join(names, ", ")
}
