package k8sauditovh

import (
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
	"github.com/falcosecurity/plugins/plugins/k8saudit/pkg/k8saudit"

	"log"
)

var (
	ID          uint32
	Name        string
	Description string
	Contact     string
	Version     string
	EventSource string
)

// TODO: use a URL has a parameter for the plugin
// "wss://gra1.logs.ovh.com/tail/?tk=bbbc8ce0-b2b5-4318-a23e-24eeeb69b6fe"
type PluginConfig struct {
	LDPWSURL string `json:"url"          jsonschema:"title=url,description=The LDP Websocket URL to use to get the OVHcloud MKS Audit Logs sent to a LDP data stream"`
}

// TODO: faire comme k8suadit ?
// Plugin represents our plugin
type Plugin struct {
	k8saudit.Plugin
	Logger *log.Logger
	Config PluginConfig
}

// SetInfo is used to set the Info of the plugin
func (p *Plugin) SetInfo(id uint32, name, description, contact, version, eventSource string) {
	ID = id
	Name = name
	Contact = contact
	Version = version
	EventSource = eventSource
}

// Info displays information of the plugin to Falco plugin framework
func (p *Plugin) Info() *plugins.Info {
	return &plugins.Info{
		ID:          ID,
		Name:        Name,
		Description: Description,
		Contact:     Contact,
		Version:     Version,
		EventSource: EventSource,
	}
}

// Init is called by the Falco plugin framework as first entry,
// we use it for setting default configuration values and mapping
// values from `init_config` (json format for this plugin)
func (p *Plugin) Init(config string) error {
	return nil
}

// Open is called by Falco plugin framework for opening a stream of events, we call that an instance
func (Plugin *Plugin) Open(params string) (source.Instance, error) {
	eventC := make(chan source.PushEvent)

	// launch an async worker that listens for bitcoin tx and pushes them
	// to the event channel
	go func() {
		defer close(eventC)

		u := url.URL{Scheme: "wss", Host: "ws.blockchain.info", Path: "inv"}
		v, _ := url.QueryUnescape(u.String())

		wsChan, _, err := websocket.DefaultDialer.Dial(v, make(http.Header))
		if err != nil {
			eventC <- source.PushEvent{Err: err}
			return
		}
		defer wsChan.Close()

		err = wsChan.WriteMessage(websocket.TextMessage, []byte(`{"op": "unconfirmed_sub"}`))
		if err != nil {
			eventC <- source.PushEvent{Err: err}
			return
		}

		for {
			_, msg, err := wsChan.ReadMessage()
			if err != nil {
				eventC <- source.PushEvent{Err: err}
				return
			}
			var tx Tx
			err = json.Unmarshal(msg, &tx)
			if err != nil {
				eventC <- source.PushEvent{Err: err}
				return
			}
			for _, i := range tx.X.Inputs {
				var d []string
				for _, j := range tx.X.Out {
					d = append(d, j.Addr)
				}
				event := Event{
					Time:         tx.X.Time,
					Hash:         tx.X.Hash,
					Relayedby:    tx.X.Relayedby,
					Wallet:       i.PrevOut.Addr,
					Amount:       uint64(i.PrevOut.Value),
					Transaction:  "sent",
					Destinations: d,
				}
				m, _ := json.Marshal(event)
				eventC <- source.PushEvent{Data: m}
			}
			for _, i := range tx.X.Out {
				var d []string
				for _, j := range tx.X.Inputs {
					d = append(d, j.PrevOut.Addr)
				}
				event := Event{
					Time:        tx.X.Time,
					Hash:        tx.X.Hash,
					Relayedby:   tx.X.Relayedby,
					Wallet:      i.Addr,
					Amount:      uint64(i.Value),
					Transaction: "received",
					Sources:     d,
				}
				m, _ := json.Marshal(event)
				eventC <- source.PushEvent{Data: m}
			}

		}
	}()
	return source.NewPushInstance(eventC)
}
