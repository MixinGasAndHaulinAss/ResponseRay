package linux

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/responseray/responseray/internal/collectoringest/core"
)

// processLinuxDocker parses Docker container and image information.
func processLinuxDocker(em *core.Emitter, dirPath, ts string) int {
	liveDir := filepath.Join(dirPath, "live")
	total := 0
	total += parseDockerContainers(em, filepath.Join(liveDir, "docker_ps_-a.json"), ts)
	total += parseDockerImages(em, filepath.Join(liveDir, "docker_images.json"), ts)
	total += parseDockerNetworks(em, filepath.Join(liveDir, "docker_network_ls.json"), ts)
	total += parseDockerVolumes(em, filepath.Join(liveDir, "docker_volume_ls.json"), ts)
	total += parseDockerInfo(em, filepath.Join(liveDir, "docker_info.json"), ts)
	return total
}

func parseDockerContainers(em *core.Emitter, path, ts string) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()

	added := 0
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 4*1024*1024)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var container struct {
			ID         string `json:"ID"`
			Image      string `json:"Image"`
			Command    string `json:"Command"`
			CreatedAt  string `json:"CreatedAt"`
			Status     string `json:"Status"`
			Ports      string `json:"Ports"`
			Names      string `json:"Names"`
			State      string `json:"State"`
			RunningFor string `json:"RunningFor"`
		}
		if err := json.Unmarshal(line, &container); err != nil {
			continue
		}
		if container.ID == "" {
			continue
		}

		shortID := container.ID
		if len(shortID) > 12 {
			shortID = shortID[:12]
		}

		status := container.Status
		if status == "" {
			status = container.State
		}

		msg := fmt.Sprintf("Docker container: %s (%s) - %s", container.Names, shortID, status)
		if em.AddEvent(ts, "Docker Container", msg, "docker_container",
			"RR-Linux", "ResponseRay Linux Collector - Docker",
			"linux:docker:container", map[string]interface{}{
				"container_id":   container.ID,
				"container_name": container.Names,
				"image":          container.Image,
				"command":        container.Command,
				"status":         status,
				"ports":          container.Ports,
				"running_for":    container.RunningFor,
			}) {
			added++
		}
	}
	return added
}

func parseDockerImages(em *core.Emitter, path, ts string) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()

	added := 0
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 4*1024*1024)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var image struct {
			ID         string `json:"ID"`
			Repository string `json:"Repository"`
			Tag        string `json:"Tag"`
			CreatedAt  string `json:"CreatedAt"`
			Size       string `json:"Size"`
		}
		if err := json.Unmarshal(line, &image); err != nil {
			continue
		}
		if image.ID == "" {
			continue
		}

		shortID := image.ID
		if len(shortID) > 12 {
			shortID = shortID[:12]
		}

		imageName := image.Repository
		if image.Tag != "" && image.Tag != "<none>" {
			imageName += ":" + image.Tag
		}

		msg := fmt.Sprintf("Docker image: %s (%s) - %s", imageName, shortID, image.Size)
		if em.AddEvent(ts, "Docker Image", msg, "docker_image",
			"RR-Linux", "ResponseRay Linux Collector - Docker",
			"linux:docker:image", map[string]interface{}{
				"image_id":   image.ID,
				"repository": image.Repository,
				"tag":        image.Tag,
				"size":       image.Size,
				"created_at": image.CreatedAt,
			}) {
			added++
		}
	}
	return added
}

func parseDockerNetworks(em *core.Emitter, path, ts string) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()

	added := 0
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 4*1024*1024)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var network struct {
			ID        string `json:"ID"`
			Name      string `json:"Name"`
			Driver    string `json:"Driver"`
			Scope     string `json:"Scope"`
			CreatedAt string `json:"CreatedAt"`
		}
		if err := json.Unmarshal(line, &network); err != nil {
			continue
		}
		if network.ID == "" {
			continue
		}

		msg := fmt.Sprintf("Docker network: %s (%s) driver=%s", network.Name, network.ID[:12], network.Driver)
		if em.AddEvent(ts, "Docker Network", msg, "docker_network",
			"RR-Linux", "ResponseRay Linux Collector - Docker",
			"linux:docker:network", map[string]interface{}{
				"network_id": network.ID,
				"name":       network.Name,
				"driver":     network.Driver,
				"scope":      network.Scope,
			}) {
			added++
		}
	}
	return added
}

func parseDockerVolumes(em *core.Emitter, path, ts string) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()

	added := 0
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 4*1024*1024)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var volume struct {
			Name       string `json:"Name"`
			Driver     string `json:"Driver"`
			Mountpoint string `json:"Mountpoint"`
		}
		if err := json.Unmarshal(line, &volume); err != nil {
			continue
		}
		if volume.Name == "" {
			continue
		}

		msg := fmt.Sprintf("Docker volume: %s driver=%s", volume.Name, volume.Driver)
		if em.AddEvent(ts, "Docker Volume", msg, "docker_volume",
			"RR-Linux", "ResponseRay Linux Collector - Docker",
			"linux:docker:volume", map[string]interface{}{
				"name":       volume.Name,
				"driver":     volume.Driver,
				"mountpoint": volume.Mountpoint,
			}) {
			added++
		}
	}
	return added
}

func parseDockerInfo(em *core.Emitter, path, ts string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}

	var info map[string]interface{}
	if err := json.Unmarshal(data, &info); err != nil {
		return 0
	}

	added := 0

	// Extract key info fields
	serverVersion, _ := info["ServerVersion"].(string)
	containers, _ := info["Containers"].(float64)
	images, _ := info["Images"].(float64)
	driver, _ := info["Driver"].(string)

	if serverVersion != "" {
		msg := fmt.Sprintf("Docker version %s: %d containers, %d images, driver=%s",
			serverVersion, int(containers), int(images), driver)
		if em.AddEvent(ts, "Docker Info", msg, "os_config",
			"RR-Linux", "ResponseRay Linux Collector - Docker",
			"linux:docker:info", map[string]interface{}{
				"setting":        "docker_info",
				"server_version": serverVersion,
				"containers":     int(containers),
				"images":         int(images),
				"driver":         driver,
			}) {
			added++
		}
	}

	return added
}

// processLinuxMounts parses mount information from live/findmnt.json.
func processLinuxMounts(em *core.Emitter, dirPath, ts string) int {
	// Parse fstab
	added := 0
	fstabPath := filepath.Join(dirPath, "artifacts", "disk", "fstab")
	if data, err := os.ReadFile(fstabPath); err == nil {
		scanner := bufio.NewScanner(strings.NewReader(string(data)))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 4 {
				continue
			}
			device := fields[0]
			mountpoint := fields[1]
			fstype := fields[2]
			options := fields[3]

			msg := fmt.Sprintf("Mount: %s -> %s (%s)", device, mountpoint, fstype)
			if em.AddEvent(ts, "Filesystem Mount", msg, "mount_entry",
				"RR-Linux", "ResponseRay Linux Collector - fstab",
				"linux:disk:mount", map[string]interface{}{
					"device":     device,
					"mountpoint": mountpoint,
					"fstype":     fstype,
					"options":    options,
				}) {
				added++
			}
		}
	}

	// Parse NFS exports
	exportsPath := filepath.Join(dirPath, "artifacts", "mounts", "exports")
	if data, err := os.ReadFile(exportsPath); err == nil {
		scanner := bufio.NewScanner(strings.NewReader(string(data)))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			msg := fmt.Sprintf("NFS export: %s", line)
			if em.AddEvent(ts, "NFS Export", msg, "nfs_export",
				"RR-Linux", "ResponseRay Linux Collector - exports",
				"linux:disk:nfs_export", map[string]interface{}{
					"export": line,
				}) {
				added++
			}
		}
	}

	return added
}

// processLinuxKernelModules parses kernel module information.
func processLinuxKernelModules(em *core.Emitter, dirPath, ts string) int {
	path := filepath.Join(dirPath, "live", "kernel_lsmod.txt")
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}

	added := 0
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	first := true
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if first {
			first = false
			if strings.HasPrefix(line, "Module") {
				continue
			}
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		modName := fields[0]
		modSize := fields[1]
		usedBy := ""
		if len(fields) >= 4 {
			usedBy = fields[3]
		}

		msg := fmt.Sprintf("Kernel module: %s (%s bytes)", modName, modSize)
		if usedBy != "" {
			msg += " used by: " + usedBy
		}
		if em.AddEvent(ts, "Kernel Module Loaded", msg, "kernel_module",
			"RR-Linux", "ResponseRay Linux Collector - lsmod",
			"linux:kernel:module", map[string]interface{}{
				"module_name": modName,
				"size":        modSize,
				"used_by":     usedBy,
			}) {
			added++
		}
	}
	return added
}
