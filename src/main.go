// Package main: Netflix Audio Stream Exfiltration PoC
//
// Attack class: Unprotected Media Stream Interception via Chrome DevTools Protocol (CDP)
// Affected platform: Netflix web streaming (all regions, all titles)
// Root cause: Audio adaptation sets in Netflix MPEG-DASH manifests are not marked
// for CENC encryption, leaving audio segment HTTP responses as cleartext fMP4 containers.
//
// This file defines the CLI argument surface and the toDownloadPath/toDownloadableURL
// helper functions used to reconstruct a downloadable CDN URL from an intercepted
// range-request URL.
//
// Compile: go build -mod=vendor -o narr.exe .
// Target:  Windows 10/11, x64, Go 1.24

package main

import (
	"context"
	"log"
	"math/rand"
	"net/url"
	"strconv"
	"strings"
)

// Args defines the operator-facing CLI interface.
// ChromeURL defaults to the standard CDP WebSocket endpoint exposed when Chrome
// is launched with --remote-debugging-port=9222.
type Args struct {
	VideoURL    *url.URL `arg:"positional,required" help:"Netflix watch URL. Example: https://www.netflix.com/watch/<videoId>?trackId=<trackId>"`
	DownloadDir string   `arg:"positional" default:"." help:"Output directory for captured audio files."`
	ChromeURL   *url.URL `arg:"-c, --chrome-url" default:"http://127.0.0.1:9222" help:"CDP endpoint URL."`
}

var Version string

func (Args) Version() string {
	return Version
}

func main() {
	args := &Args{}
	mustParse(args)

	// Attach to the CDP endpoint. Retries indefinitely until Chrome is reachable.
	// In the PoC workflow, Chrome is launched by launch.ps1 before this binary is invoked.
	ctx := context.Background()
	chromeURL := args.ChromeURL.String()
	chrome := tryConnectToChromeUntilSuccess(ctx, chromeURL)

	log.Printf("Connected to Chrome CDP at %s", chromeURL)

	// Initialize the download queue (up to 8 concurrent segment downloads).
	q := NewDownloadQueue()
	defer q.Release()

	q.OnStatusReceived(func(status DownloadStatus) {
		task := status.Task()
		switch s := status.(type) {
		case Queuing:
			break
		case Begin:
			log.Printf("[download] [%s] %s -> %s", s.TaskId(), task.VideoUrl, task.FullFilePath)
		case Finished:
			log.Printf("[done] [%s] %s => %s (%d bytes in %.3fs)", s.TaskId(), task.VideoUrl, task.FullFilePath, s.BytesReceived(), s.Duration().Seconds())
		}
	})

	nflx := NewNFLX(chrome)

	// Navigate the attached Chrome instance to the target Netflix title.
	// The Netflix player will initialize, request a DASH manifest, and begin
	// fetching media segments. The CDP listener in nflx.go intercepts those requests.
	err := nflx.NavigateTo(ctx, args.VideoURL.String())
	if err != nil {
		log.Fatal(err)
	}

	// Event loop: block on CDP events until the WebSocket connection closes.
	var browserURL = args.VideoURL.String()
	for events := range nflx.Listen(ctx) {
		switch events.evType {
		case MediaUrlReceivedEvent:
			// An intercepted media segment URL was identified as a candidate.
			// Strip the byte-range path component before re-fetching.
			err := q.QueueDownload(DownloadTask{
				SrcURL:      toDownloadableURL(string(events.payload)),
				VideoUrl:    browserURL,
				DownloadDir: args.DownloadDir,
			})
			if err != nil {
				log.Println(err)
			}
		case NavigatedEvent:
			log.Printf("[navigate] %s", events.payload)
			browserURL = string(events.payload)
		}
	}
}

// toDownloadableURL strips the byte-range path suffix from an intercepted segment URL.
// Netflix CDN range requests carry the range as a URL path component: /range/0-<N>.
// Removing the path causes the CDN to serve the full resource, which is identical
// to the complete audio segment.
func toDownloadableURL(audioURL string) string {
	u, err := url.Parse(audioURL)
	if err != nil {
		log.Fatal(err)
	}
	u.Path = ""
	return u.String()
}

// toDownloadPath constructs the output file path from the Netflix videoId, trackId,
// and the probed codec (AAC or xHE-AAC). A random suffix prevents collisions when
// multiple segments for the same title are captured in a single session.
func toDownloadPath(videoURL string, downloadDir string, fi probeInfo) string {
	u, err := url.Parse(videoURL)
	if err != nil {
		log.Fatal(err)
	}

	var audCodec = ".aac"
	if fi.isXHEAAC {
		audCodec = ".xhe-aac"
	}

	if strings.HasPrefix(u.Path, "/watch") && u.Query().Has("trackId") {
		videoId := strings.TrimLeft(u.Path, "/watch/")
		trackId := u.Query().Get("trackId")
		return downloadDir + "/" + videoId + "-" + trackId + "-" + strconv.Itoa(rand.Int()) + audCodec + ".mp4a"
	}

	return downloadDir + "/" + "DL-" + strconv.Itoa(rand.Int()) + audCodec + ".mp4a"
}
