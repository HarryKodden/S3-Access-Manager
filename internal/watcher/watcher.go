package watcher

import (
	"context"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/sirupsen/logrus"
)

// SyncService interface for triggering syncs
type SyncService interface {
	SyncAllSCIM(ctx context.Context) error
}

// FileWatcher watches directories for changes and triggers sync operations
type FileWatcher struct {
	watcher     *fsnotify.Watcher
	syncService SyncService
	logger      *logrus.Logger
	debouncer   *Debouncer
	watchedDirs []string
}

// Debouncer prevents rapid successive syncs by batching events
type Debouncer struct {
	mu       sync.Mutex
	timer    *time.Timer
	callback func()
	delay    time.Duration
}

// NewDebouncer creates a new debouncer with the specified delay
func NewDebouncer(delay time.Duration, callback func()) *Debouncer {
	return &Debouncer{
		callback: callback,
		delay:    delay,
	}
}

// Trigger schedules the callback to run after the delay
// If called again before the delay expires, the timer is reset
func (d *Debouncer) Trigger() {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.timer != nil {
		d.timer.Stop()
	}

	d.timer = time.AfterFunc(d.delay, func() {
		d.callback()
	})
}

// NewFileWatcher creates a new file watcher
func NewFileWatcher(syncService SyncService, logger *logrus.Logger) (*FileWatcher, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	fw := &FileWatcher{
		watcher:     watcher,
		syncService: syncService,
		logger:      logger,
		watchedDirs: []string{},
	}

	// Create debouncer with 2 second delay to batch rapid changes
	fw.debouncer = NewDebouncer(2*time.Second, func() {
		fw.triggerSync()
	})

	return fw, nil
}

// AddDirectory adds a directory to watch for changes
func (fw *FileWatcher) AddDirectory(dir string) error {
	absPath, err := filepath.Abs(dir)
	if err != nil {
		return err
	}

	if err := fw.watcher.Add(absPath); err != nil {
		return err
	}

	fw.watchedDirs = append(fw.watchedDirs, absPath)
	fw.logger.WithField("directory", absPath).Info("Watching directory for changes")
	return nil
}

// Start begins watching for file system events
func (fw *FileWatcher) Start(ctx context.Context) {
	go func() {
		fw.logger.Info("File watcher started")
		defer fw.logger.Info("File watcher stopped")

		for {
			select {
			case event, ok := <-fw.watcher.Events:
				if !ok {
					return
				}

				// Only trigger on write, create, remove, rename events
				if event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Remove|fsnotify.Rename) != 0 {
					// Only process .json files (SCIM data files)
					if filepath.Ext(event.Name) == ".json" {
						fw.logger.WithFields(logrus.Fields{
							"file":      event.Name,
							"operation": event.Op.String(),
						}).Info("Detected file change")

						// Debounce to avoid multiple rapid syncs
						fw.debouncer.Trigger()
					}
				}

			case err, ok := <-fw.watcher.Errors:
				if !ok {
					return
				}
				fw.logger.WithError(err).Error("File watcher error")

			case <-ctx.Done():
				fw.logger.Info("File watcher context cancelled")
				return
			}
		}
	}()
}

// triggerSync performs the actual sync operation
func (fw *FileWatcher) triggerSync() {
	fw.logger.Info("Triggering SCIM-to-IAM sync due to file changes")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := fw.syncService.SyncAllSCIM(ctx); err != nil {
		fw.logger.WithError(err).Error("Failed to sync SCIM data after file change")
	} else {
		fw.logger.Info("Successfully synced SCIM data after file change")
	}
}

// Close stops watching and cleans up resources
func (fw *FileWatcher) Close() error {
	if fw.debouncer.timer != nil {
		fw.debouncer.timer.Stop()
	}
	return fw.watcher.Close()
}
