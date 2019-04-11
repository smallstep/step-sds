package main

import (
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/smallstep/cli/command"
	"github.com/smallstep/cli/command/version"
	"github.com/smallstep/cli/config"
	"github.com/smallstep/cli/usage"
	"github.com/smallstep/step-sds/sds"
	"github.com/urfave/cli"

	// Enabled commands
	_ "github.com/smallstep/step-sds/commands"

	// Profiling and debugging
	_ "net/http/pprof"
)

// Version is set by an LDFLAG at build time representing the git tag or commit
// for the current release
var Version = "N/A"

// BuildTime is set by an LDFLAG at build time representing the timestamp at
// the time of build
var BuildTime = "N/A"

var placeholderString = regexp.MustCompile(`<.*?>`)

var AppHelpTemplate = `## NAME
**{{.HelpName}}** -- {{.Usage}}

## USAGE
{{if .UsageText}}{{.UsageText}}{{else}}**{{.HelpName}}**{{if .Commands}} <command>{{end}} {{if .ArgsUsage}}{{.ArgsUsage}}{{else}}_[arguments]_{{end}}{{end}}{{if .Description}}

## DESCRIPTION
{{.Description}}{{end}}{{if .VisibleCommands}}

## COMMANDS

{{range .VisibleCategories}}{{if .Name}}{{.Name}}:{{end}}
|||
|---|---|{{range .VisibleCommands}}
| **{{join .Names ", "}}** | {{.Usage}} |{{end}}
{{end}}{{if .VisibleFlags}}{{end}}

## OPTIONS

{{range $index, $option := .VisibleFlags}}{{if $index}}
{{end}}{{$option}}
{{end}}{{end}}{{if .Copyright}}{{if len .Authors}}

## AUTHOR{{with $length := len .Authors}}{{if ne 1 $length}}S{{end}}{{end}}:

{{range $index, $author := .Authors}}{{if $index}}
{{end}}{{$author}}{{end}}{{end}}{{if .Version}}{{if not .HideVersion}}

## ONLINE

This documentation is available online at https://github.com/smallstep/step-sds

## VERSION

{{.Version}}{{end}}{{end}}

## COPYRIGHT

{{.Copyright}}
{{end}}
`

func init() {
	config.Set("Smallstep SDS", Version, BuildTime)
	sds.Identifier = config.Version()
	rand.Seed(time.Now().UnixNano())
}

func panicHandler() {
	if r := recover(); r != nil {
		if os.Getenv("STEPDEBUG") == "1" {
			fmt.Fprintf(os.Stderr, "%s\n", config.Version())
			fmt.Fprintf(os.Stderr, "Release Date: %s\n\n", config.ReleaseDate())
			panic(r)
		} else {
			fmt.Fprintln(os.Stderr, "Something unexpected happened.")
			fmt.Fprintln(os.Stderr, "If you want to help us debug the problem, please run:")
			fmt.Fprintf(os.Stderr, "STEPDEBUG=1 %s\n", strings.Join(os.Args, " "))
			fmt.Fprintln(os.Stderr, "and send the output to info@smallstep.com")
			os.Exit(2)
		}
	}
}

func main() {
	defer panicHandler()
	// Override global framework components
	cli.VersionPrinter = func(c *cli.Context) {
		version.Command(c)
	}
	cli.AppHelpTemplate = AppHelpTemplate
	cli.SubcommandHelpTemplate = usage.SubcommandHelpTemplate
	cli.CommandHelpTemplate = usage.CommandHelpTemplate
	cli.HelpPrinter = usage.HelpPrinter
	cli.FlagNamePrefixer = usage.FlagNamePrefixer
	cli.FlagStringer = stringifyFlag

	// Configure cli app
	app := cli.NewApp()
	app.Name = "step-sds"
	app.HelpName = "step-sds"
	app.Usage = "secret discovery service"
	app.Version = config.Version()
	app.Commands = command.Retrieve()
	app.Flags = append(app.Flags, cli.HelpFlag)
	app.EnableBashCompletion = true
	app.Copyright = "(c) 2019 Smallstep Labs, Inc."
	app.Usage = "secret discovery service for secure certificate distribution"

	// All non-successful output should be written to stderr
	app.Writer = os.Stdout
	app.ErrWriter = os.Stderr

	// Start the golang debug logger if environment variable is set.
	// See https://golang.org/pkg/net/http/pprof/
	debugProfAddr := os.Getenv("STEP_PROF_ADDR")
	if debugProfAddr != "" {
		go func() {
			log.Println(http.ListenAndServe(debugProfAddr, nil))
		}()
	}

	if err := app.Run(os.Args); err != nil {
		if os.Getenv("STEPDEBUG") == "1" {
			fmt.Fprintf(os.Stderr, "%+v\n", err)
		} else {
			fmt.Fprintln(os.Stderr, err)
		}
		os.Exit(1)
	}
}

func flagValue(f cli.Flag) reflect.Value {
	fv := reflect.ValueOf(f)
	for fv.Kind() == reflect.Ptr {
		fv = reflect.Indirect(fv)
	}
	return fv
}

func stringifyFlag(f cli.Flag) string {
	fv := flagValue(f)
	usage := fv.FieldByName("Usage").String()
	placeholder := placeholderString.FindString(usage)
	if placeholder == "" {
		placeholder = "<value>"
	}
	return cli.FlagNamePrefixer(fv.FieldByName("Name").String(), placeholder) + "\t" + usage
}
