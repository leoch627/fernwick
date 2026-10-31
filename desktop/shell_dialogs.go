package main

import (
	"github.com/wailsapp/wails/v3/pkg/application"
	"sync"
)

func ask(app *application.App, title, message string, buttons []string, cancel int) int {
	done := make(chan int, 1)
	var once sync.Once
	dialog := app.Dialog.Question().SetTitle(title).SetMessage(message)
	for i, label := range buttons {
		index := i
		button := dialog.AddButton(label).OnClick(func() { once.Do(func() { done <- index }) })
		if index == cancel {
			button.SetAsCancel()
		}
		if index == 0 {
			button.SetAsDefault()
		}
	}
	dialog.Show()
	return <-done
}
