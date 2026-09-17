// queue.go: Concurrent download queue with audio/video discrimination
//
// After nflx.go intercepts a media segment URL, this layer:
//   1. Re-fetches the URL via a standard HTTP GET (no authentication required;
//      the CDN serves the resource to any requestor with the correct URL).
//   2. Reads the first 3000 bytes and passes them to probe.go for MPEG-4 box parsing.
//   3. If the container is identified as an audio track (AAC or xHE-AAC), the remaining
//      bytes are streamed to disk.
//   4. If the container is identified as a video track (Widevine-CENC encrypted fMP4),
//      the download is discarded. The ciphertext would be unplayable without the
//      Widevine decryption key, which never leaves the browser's CDM.
//
// Security relevance:
//   The re-fetch in step 1 demonstrates that Netflix CDN audio segment URLs are not
//   bound to the originating session. Any process that obtains the URL can independently
//   download the full audio resource without presenting a Netflix session cookie or
//   any other authentication credential. This is consistent with the lack of CENC
//   encryption on audio segments: if the content were encrypted, unauthenticated
//   download would be harmless. Because it is cleartext, the URL alone is sufficient
//   to exfiltrate the content.

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/golang-queue/queue"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

// DownloadQueue manages up to 8 concurrent segment download workers.
type DownloadQueue struct {
	statusMsgs chan DownloadStatus
	*queue.Queue
}

func NewDownloadQueue() *DownloadQueue {
	return &DownloadQueue{
		Queue:      queue.NewPool(8),
		statusMsgs: make(chan DownloadStatus, 50),
	}
}

// DownloadTask carries the metadata for a single segment download job.
type DownloadTask struct {
	SrcURL       string // CDN URL to fetch (no auth required)
	VideoUrl     string // Netflix watch URL (used for output naming)
	DownloadDir  string
	FullFilePath string
}

type DownloadStatus interface {
	TaskId() string
	Task() DownloadTask
}

func (q *DownloadQueue) OnStatusReceived(f func(DownloadStatus)) {
	go func() {
		for msg := range q.statusMsgs {
			f(msg)
		}
	}()
}

// QueueDownload enqueues a segment download job. The job performs the following:
//
//  1. HTTP GET the CDN URL without any Netflix session credential.
//  2. Read 3000 bytes and probe the MPEG-4 container type.
//  3. Discard if video (encrypted); persist if audio (cleartext).
func (q *DownloadQueue) QueueDownload(t DownloadTask) error {
	go func(t DownloadTask) {
		var taskId = newTaskId()
		q.statusMsgs <- Queuing{&taskInfo{taskId, t}}

		err := q.QueueTask(func(ctx context.Context) error {
			start := time.Now()
			var browserURL = t.VideoUrl
			var srcURL = t.SrcURL
			var downloadDir = t.DownloadDir

			// Step 1: fetch without authentication.
			// No Netflix cookie, no Authorization header. The CDN serves the segment
			// to any client presenting the correct URL. This confirms the URL is the
			// sole access control mechanism for audio content.
			resp, err := http.Get(srcURL)
			if err != nil {
				return err
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("unexpected status %d for %s", resp.StatusCode, browserURL)
			}

			// Step 2: read header bytes for container probing.
			header := make([]byte, 3000)
			if _, err = io.ReadAtLeast(resp.Body, header, 3000); err != nil {
				return fmt.Errorf("can't read header: %s", err)
			}

			// Step 3: discriminate audio vs video via MPEG-4 box parsing (probe.go).
			isAudio, fInfo, err := probeFileFormat(header)
			if err != nil {
				return fmt.Errorf("error probing file format of %s: %w", browserURL, err)
			}

			// Video segments are Widevine-CENC encrypted. Even if downloaded, the bytes
			// are ciphertext and require a decryption key bound to the Chrome CDM.
			// Discarding them here keeps the PoC focused on the demonstrable audio gap.
			if !isAudio {
				return nil
			}

			downloadPath := toDownloadPath(browserURL, downloadDir, fInfo)
			t.FullFilePath = downloadPath

			q.statusMsgs <- Begin{&taskInfo{taskId, t}}

			out, err := os.Create(t.FullFilePath)
			if err != nil {
				return err
			}
			defer out.Close()

			// Write the already-read header bytes first.
			_, err = out.Write(header)
			if err != nil {
				return err
			}

			// Stream the remainder of the response body directly to disk.
			n, err := io.Copy(out, resp.Body)
			if err != nil {
				return err
			}

			q.statusMsgs <- Finished{
				taskInfo:      &taskInfo{taskId, t},
				bytesReceived: n,
				duration:      time.Since(start),
			}

			return nil
		})
		if err != nil {
			return
		}
	}(t)

	return nil
}

type taskInfo struct {
	taskId string
	task   DownloadTask
}

func (d *taskInfo) TaskId() string  { return d.taskId }
func (d *taskInfo) Task() DownloadTask { return d.task }

type Queuing struct{ *taskInfo }
type Begin struct{ *taskInfo }

type Finished struct {
	bytesReceived int64
	duration      time.Duration
	*taskInfo
}

func (f *Finished) BytesReceived() int64      { return f.bytesReceived }
func (f *Finished) Duration() time.Duration   { return f.duration }

func newTaskId() string {
	bytes := make([]byte, 6)
	if _, err := rand.Read(bytes); err != nil {
		log.Fatal(err)
	}
	return hex.EncodeToString(bytes)
}
