package output

import (
	"strings"
	"sync"

	"github.com/charmbracelet/log"
	jsoniter "github.com/json-iterator/go"
	"github.com/json-iterator/go/extra"
	"gopkg.in/yaml.v3"

	"github.com/natesales/q/util"
)

// json-iterator extensions are process-global: register the naming strategy once
// so concurrent printers (daemon mode) do not race on the registry.
var lowerCaseNames sync.Once

func (p Printer) PrintStructured(entries []*Entry) {
	var marshaler func(any) ([]byte, error)
	if p.Opts.Format == "json" {
		lowerCaseNames.Do(func() { extra.SetNamingStrategy(strings.ToLower) })
		json := jsoniter.ConfigCompatibleWithStandardLibrary
		marshaler = json.Marshal
	} else { // yaml
		marshaler = yaml.Marshal
	}

	b, err := marshaler(entries)
	if err != nil {
		log.Fatalf("error marshaling output: %s", err)
	}

	util.MustWriteln(p.Out, string(b))
}
