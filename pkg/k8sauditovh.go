package k8sauditovh

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
	"github.com/falcosecurity/plugins/plugins/k8saudit/pkg/k8saudit"

	"github.com/gorilla/websocket"

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

type PluginConfig struct {
}

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

func (p *Plugin) OpenParams() ([]sdk.OpenParam, error) {
	return []sdk.OpenParam{
		{Value: "", Desc: "The LDP Websocket URL to use to get the OVHcloud MKS Audit Logs sent to a LDP data stream"},
	}, nil
}

// Open is called by Falco plugin framework for opening a stream of events, we call that an instance
func (Plugin *Plugin) Open(ovhLDPURL string) (source.Instance, error) {

	if ovhLDPURL == "" {
		return nil, fmt.Errorf("OVHcloud LDP URL can't be empty")
	}

	eventC := make(chan source.PushEvent)

	// launch an async worker that listens for bitcoin tx and pushes them
	// to the event channel
	go func() {
		defer close(eventC)

		u := url.URL{Scheme: "wss", Host: ovhLDPURL, Path: "inv"}
		v, _ := url.QueryUnescape(u.String())

		wsChan, _, err := websocket.DefaultDialer.Dial(v, make(http.Header))
		if err != nil {
			eventC <- source.PushEvent{Err: err}
			return
		}
		defer wsChan.Close()

		for {
			_, msg, err := wsChan.ReadMessage()
			if err != nil {
				eventC <- source.PushEvent{Err: err}
				return
			}

			// Parse audit events payload thanls to k8saudit extract parse and extract methods
			values, err := Plugin.Plugin.ParseAuditEventsPayload(msg)
			if err != nil {
				Plugin.Logger.Println(err)
				continue
			}
			for _, j := range values {
				if j.Err != nil {
					Plugin.Logger.Println(j.Err)
					continue
				}

				//eventC <- source.PushEvent{Data: *j}
				eventC <- *j
			}

		}
	}()
	return source.NewPushInstance(eventC)
}
