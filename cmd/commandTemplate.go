package cmd

import "github.com/manifoldco/promptui"

var commandTemplates = &promptui.PromptTemplates{
	Success:         `{{ . | cyan }}`,
	ValidationError: `{{ . | red }}`,
}
