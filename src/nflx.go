// nflx.go: CDP attachment and DASH segment interception
//
// This file implements the core interception logic.
//
// Mechanism:
//   Netflix streams media via MPEG-DASH. The browser (Chrome) fetches audio and video
//   segments as HTTP range requests to Netflix CDN hosts. Each request triggers a
//   CDP Network.responseReceived event. By subscribing to this event, this process
//   observes every URL the Netflix player fetches in real time.
//
// URL identification:
//   DASH segment requests are identified by the presence of "/range/0-" in the URL path.
//   This prefix marks the initial byte-range request for each new segment, as opposed to
//   subsequent range requests for buffering. Filtering on this prefix ensures each logical
//   segment is captured exactly once.
//
// DRM note:
//   Video segments are Widevine-CENC encrypted. The CDP Network layer exposes the URL
//   of the ciphertext response, but the plaintext is never accessible through CDP.
//   Audio segments are not CENC-encrypted; the response body is a cleartext fMP4 container.
//   The queue.go layer discriminates between the two using box-level MPEG-4 parsing.

package main

import (
	"context"
	"github.com/mafredri/cdp"
	"github.com/mafredri/cdp/protocol/network"
	"github.com/mafredri/cdp/protocol/page"
	"golang.org/x/sync/errgroup"
	"log"
	"strings"
)

type NFlX struct {
	chrome *cdp.Client
}

func NewNFLX(chrome *cdp.Client) *NFlX {
	return &NFlX{
		chrome: chrome,
	}
}

type event struct {
	evType  int
	payload []byte
}

const MediaUrlReceivedEvent = 0
const NavigatedEvent = 1

// Listen attaches to the CDP Network and Page domains and returns a channel
// of events. Two event types are emitted:
//
//   - MediaUrlReceivedEvent: a DASH segment URL matching the /range/0- pattern was observed.
//   - NavigatedEvent: the browser navigated to a new URL (e.g., from title page to player).
//
// The channel is closed when the CDP WebSocket connection terminates (e.g., Chrome exits).
func (n *NFlX) Listen(ctx context.Context) chan event {
	c := n.chrome

	// Subscribe to Network.responseReceived: fires for every HTTP response in the page.
	responseReceived, err := c.Network.ResponseReceived(ctx)
	if err != nil {
		log.Fatal(err)
	}

	// Subscribe to Page.navigatedWithinDocument: fires on SPA-style navigation
	// (hash or history API changes) without a full page reload.
	navigated, err := c.Page.NavigatedWithinDocument(ctx)
	if err != nil {
		log.Fatal(err)
	}

	// Enable the Network and Page CDP domains to begin receiving events.
	if err = runBatch(
		func() error { return c.Network.Enable(ctx, network.NewEnableArgs()) },
		func() error { return c.Page.Enable(ctx) },
	); err != nil {
		log.Fatal(err)
	}

	ev := func(navigated page.NavigatedWithinDocumentClient, responseReceived network.ResponseReceivedClient) chan event {
		events := make(chan event)
		go func() {
			defer navigated.Close()
			defer responseReceived.Close()
			for {
				select {
				case <-navigated.Ready():
					ev, err := navigated.Recv()
					if err != nil {
						// CDP connection closed; terminate the event loop.
						log.Fatal(err)
					}
					events <- event{NavigatedEvent, []byte(ev.URL)}

				case <-responseReceived.Ready():
					ev, err := responseReceived.Recv()
					if err != nil {
						log.Fatal(err)
					}

					// isMediaURL filters for DASH segment initial range requests.
					// Both audio and video segments match this pattern; codec-level
					// discrimination occurs downstream in queue.go.
					if isMediaURL(ev.Response.URL) {
						events <- event{MediaUrlReceivedEvent, []byte(ev.Response.URL)}
					}
				}
			}
		}()
		return events
	}(navigated, responseReceived)

	return ev
}

// isMediaURL identifies DASH media segment URLs by matching the /range/0- path segment.
// Netflix CDN URLs for initial segment range requests have the form:
//
//	https://<cdnhost>/...?<params>#/range/0-<N>
//
// Subsequent range requests for the same segment (for buffering) use non-zero offsets
// and are not matched, preventing duplicate downloads.
func isMediaURL(u string) bool {
	return strings.Contains(u, "/range/0-")
}

// NavigateTo instructs the attached Chrome instance to load the given URL.
// This triggers the Netflix player initialization and DASH manifest fetch.
func (n *NFlX) NavigateTo(ctx context.Context, url string) error {
	navArgs := page.NewNavigateArgs(url)
	_, err := n.chrome.Page.Navigate(ctx, navArgs)
	if err != nil {
		return err
	}
	return nil
}

type runBatchFunc func() error

// runBatch executes a set of functions concurrently and returns the first error encountered.
func runBatch(fn ...runBatchFunc) error {
	eg := errgroup.Group{}
	for _, f := range fn {
		eg.Go(f)
	}
	return eg.Wait()
}
