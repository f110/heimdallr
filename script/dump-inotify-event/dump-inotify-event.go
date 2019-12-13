package main

import (
	"log"
	"os"

	"github.com/fsnotify/fsnotify"
)

func main() {
	dir := os.Args[1]
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		panic(err)
	}
	if err := watcher.Add(dir); err != nil {
		panic(err)
	}

	for {
		event, ok := <-watcher.Events
		if !ok {
			panic("close channel")
		}
		log.Print(event)
	}
}
