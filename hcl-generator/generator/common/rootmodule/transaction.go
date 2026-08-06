package rootmodule

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"hcl-generator/generator/common"
)

// CommitPreparedFiles cree les repertoires requis puis ecrit tous les fichiers
// par la transaction commune. Les nouveaux repertoires vides sont retires si
// l'ecriture echoue.
func CommitPreparedFiles(prepared map[string][]byte, directories []string) error {
	directorySet := make(map[string]struct{})
	for _, directory := range directories {
		directorySet[filepath.Clean(directory)] = struct{}{}
	}
	for path := range prepared {
		directorySet[filepath.Dir(filepath.Clean(path))] = struct{}{}
	}

	ordered := make([]string, 0, len(directorySet))
	for directory := range directorySet {
		ordered = append(ordered, directory)
	}
	sort.Slice(ordered, func(i, j int) bool {
		return len(ordered[i]) < len(ordered[j])
	})

	var created []string
	for _, directory := range ordered {
		if _, err := os.Stat(directory); err == nil {
			continue
		} else if !os.IsNotExist(err) {
			rollbackDirectories(created)
			return fmt.Errorf("impossible d'inspecter %s : %w", directory, err)
		}
		if err := os.MkdirAll(directory, 0o755); err != nil {
			rollbackDirectories(created)
			return fmt.Errorf("impossible de creer %s : %w", directory, err)
		}
		created = append(created, directory)
	}

	if err := common.CommitFilePathsAtomically(prepared); err != nil {
		rollbackDirectories(created)
		return err
	}
	return nil
}

func rollbackDirectories(directories []string) {
	sort.Slice(directories, func(i, j int) bool {
		return len(directories[i]) > len(directories[j])
	})
	for _, directory := range directories {
		_ = os.Remove(directory)
	}
}
