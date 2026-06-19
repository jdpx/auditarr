package analysis

import (
	"testing"

	"github.com/jdpx/auditarr/internal/models"
)

// qBittorrent reports paths under its own mount (/data), while auditarr scans the
// host torrent_root (/mnt/media-arr/torrents). Matching must work across that gap.
func TestBelongsToActiveTorrent(t *testing.T) {
	e := &Engine{torrentRoot: "/mnt/media-arr/torrents"}
	idx := e.buildTorrentFileIndex([]models.Torrent{
		{SavePath: "/data/tv-sonarr", Files: []string{"The.Boys.S05E01.mkv"}},              // single-file
		{SavePath: "/data/radarr/Avatar (2009)", Files: []string{"Avatar.2009.mkv"}},       // file in release dir
		{SavePath: "/data/tv-sonarr", Files: []string{"Top Gear S16/Top Gear S16E07.mp4"}}, // multi-file torrent
	})

	cases := []struct {
		name string
		path string
		want bool
	}{
		{"single-file match across mounts", "/mnt/media-arr/torrents/tv-sonarr/The.Boys.S05E01.mkv", true},
		{"release-dir match", "/mnt/media-arr/torrents/radarr/Avatar (2009)/Avatar.2009.mkv", true},
		{"nested multi-file match", "/mnt/media-arr/torrents/tv-sonarr/Top Gear S16/Top Gear S16E07.mp4", true},
		{"genuinely abandoned (not in any torrent)", "/mnt/media-arr/torrents/tv-sonarr/Abandoned.S01E01.mkv", false},
		{"same basename, different path is not a match", "/mnt/media-arr/torrents/radarr/The.Boys.S05E01.mkv", false},
		{"outside torrent root", "/mnt/media-arr/media/tv/The.Boys.S05E01.mkv", false},
	}
	for _, c := range cases {
		if got := e.belongsToActiveTorrent(c.path, idx); got != c.want {
			t.Errorf("%s: belongsToActiveTorrent(%q) = %v, want %v", c.name, c.path, got, c.want)
		}
	}
}

func TestClassifyTorrentFile_ActiveTorrentNotOrphaned(t *testing.T) {
	notImported := models.MediaFile{IsHardlinked: false}

	// Not hardlinked + not Arr-tracked, but still an active torrent -> NOT orphaned.
	if cls, incl := ClassifyTorrentFile(notImported, nil, 0, true); cls != models.MediaHealthy || !incl {
		t.Errorf("active torrent file classified %q (incl=%v), want healthy", cls, incl)
	}
	// Not hardlinked + not Arr-tracked + not in any torrent -> orphaned.
	if cls, incl := ClassifyTorrentFile(notImported, nil, 0, false); cls != models.MediaOrphanedDownload || !incl {
		t.Errorf("abandoned file classified %q (incl=%v), want orphaned_download", cls, incl)
	}
}
