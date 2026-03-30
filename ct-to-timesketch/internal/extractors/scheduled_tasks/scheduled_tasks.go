package scheduled_tasks

import (
	"encoding/xml"
	"fmt"
	"strings"

	"github.com/NCLGISA/ct-to-timesketch/internal/cache"
	"github.com/NCLGISA/ct-to-timesketch/internal/converter"
	"github.com/NCLGISA/ct-to-timesketch/internal/extractors"
	"github.com/NCLGISA/ct-to-timesketch/internal/progress"
)

func init() { extractors.Register(&Extractor{}) }

type Extractor struct{}

func (e *Extractor) Name() string        { return "scheduled_tasks" }
func (e *Extractor) Description() string { return "Scheduled Tasks XML files" }

type taskXML struct {
	XMLName          xml.Name `xml:"Task"`
	RegistrationInfo struct {
		Date        string `xml:"Date"`
		Author      string `xml:"Author"`
		Description string `xml:"Description"`
		URI         string `xml:"URI"`
	} `xml:"RegistrationInfo"`
	Actions struct {
		Exec []struct {
			Command   string `xml:"Command"`
			Arguments string `xml:"Arguments"`
		} `xml:"Exec"`
	} `xml:"Actions"`
	Principals struct {
		Principal struct {
			UserID   string `xml:"UserId"`
			RunLevel string `xml:"RunLevel"`
		} `xml:"Principal"`
	} `xml:"Principals"`
}

func (e *Extractor) Extract(cachePath string, conv *converter.Converter, idx *cache.Index) (int, error) {
	if idx == nil {
		return 0, nil
	}
	files, err := idx.GetCollectedFiles(`\.xml$`, `Tasks`)
	if err != nil {
		return 0, err
	}
	added := 0
	for _, f := range files {
		decoded, err := extractors.GetFileContent(f)
		if err != nil || len(decoded) == 0 {
			continue
		}

		var task taskXML
		if err := xml.Unmarshal(decoded, &task); err != nil {
			continue
		}

		ts := task.RegistrationInfo.Date
		if ts == "" {
			continue
		}
		ts = converter.NormalizeTimestamp(ts)
		if ts == "" {
			continue
		}

		taskName := task.RegistrationInfo.URI
		if taskName == "" {
			taskName = strings.TrimSuffix(f.Filename, ".xml")
		}

		var command string
		if len(task.Actions.Exec) > 0 {
			command = task.Actions.Exec[0].Command
			if task.Actions.Exec[0].Arguments != "" {
				command += " " + task.Actions.Exec[0].Arguments
			}
		}

		msg := fmt.Sprintf("Scheduled Task: %s", taskName)
		if command != "" {
			msg += fmt.Sprintf(" -> %s", command)
		}

		attrs := map[string]interface{}{
			"task_name":   taskName,
			"author":      task.RegistrationInfo.Author,
			"description": task.RegistrationInfo.Description,
			"command":     command,
			"user_id":     task.Principals.Principal.UserID,
			"run_level":   task.Principals.Principal.RunLevel,
			"file_path":   f.Path + "/" + f.Filename,
		}
		if conv.AddEvent(ts, "Task Registration Date", msg,
			"scheduled_task_xml", "CT-Tasks",
			"CyberTriage Scheduled Tasks",
			"windows:tasks:job", attrs) {
			added++
		}
	}
	progress.Info(fmt.Sprintf("Scheduled Tasks: %d tasks parsed", added))
	return added, nil
}
