package common

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

func CommitFilesAtomically(basePath string, contents map[string][]byte) error {
	paths := make(map[string][]byte, len(contents))
	for filename, content := range contents {
		paths[filepath.Join(basePath, filename)] = content
	}
	return CommitFilePathsAtomically(paths)
}

// CommitFilePathsAtomically remplace un ensemble de fichiers, y compris dans
// plusieurs repertoires, comme une seule transaction. Chaque original est
// sauvegarde avant remplacement et tous les fichiers deja remplaces sont
// restaures si une etape echoue.
func CommitFilePathsAtomically(contents map[string][]byte) error {
	filenames := make([]string, 0, len(contents))
	for filename := range contents {
		filenames = append(filenames, filename)
	}
	sort.Strings(filenames)

	staged := make([]TransactionFile, 0, len(filenames))
	commitSucceeded := false
	defer func() {
		for _, file := range staged {
			_ = os.Remove(file.tempPath)
			if file.backupPath != "" && (!file.hadOriginal || commitSucceeded) {
				_ = os.Remove(file.backupPath)
			}
		}
	}()

	for _, filename := range filenames {
		path := filepath.Clean(filename)
		basePath := filepath.Dir(path)
		tempFile, err := os.CreateTemp(
			basePath,
			"."+filepath.Base(path)+".*.tmp",
		)
		if err != nil {
			return fmt.Errorf(
				"impossible de creer un fichier temporaire pour %s : %w",
				path,
				err,
			)
		}

		tempPath := tempFile.Name()
		staged = append(staged, TransactionFile{path: path, tempPath: tempPath})
		if _, err := tempFile.Write(contents[filename]); err != nil {
			_ = tempFile.Close()
			return fmt.Errorf("impossible d'ecrire %s : %w", tempPath, err)
		}
		if err := tempFile.Close(); err != nil {
			return fmt.Errorf("impossible de fermer %s : %w", tempPath, err)
		}
	}

	committed := 0
	for index := range staged {
		file := &staged[index]
		info, err := os.Stat(file.path)
		if err == nil {
			if info.IsDir() {
				return withRollback(
					fmt.Errorf("la cible %s est un dossier", file.path),
					rollbackFiles(staged[:committed]),
				)
			}
			if err := os.Chmod(file.tempPath, info.Mode()); err != nil {
				return withRollback(
					fmt.Errorf("impossible de conserver les permissions de %s : %w", file.path, err),
					rollbackFiles(staged[:committed]),
				)
			}

			backupFile, err := os.CreateTemp(
				filepath.Dir(file.path),
				"."+filepath.Base(file.path)+".*.backup",
			)
			if err != nil {
				return withRollback(
					fmt.Errorf("impossible de preparer le backup de %s : %w", file.path, err),
					rollbackFiles(staged[:committed]),
				)
			}
			file.backupPath = backupFile.Name()
			if err := backupFile.Close(); err != nil {
				return withRollback(
					fmt.Errorf("impossible de fermer le backup de %s : %w", file.path, err),
					rollbackFiles(staged[:committed]),
				)
			}
			if err := os.Remove(file.backupPath); err != nil {
				return withRollback(
					fmt.Errorf("impossible de preparer le chemin de backup de %s : %w", file.path, err),
					rollbackFiles(staged[:committed]),
				)
			}
			if err := os.Rename(file.path, file.backupPath); err != nil {
				return withRollback(
					fmt.Errorf("impossible de sauvegarder %s : %w", file.path, err),
					rollbackFiles(staged[:committed]),
				)
			}
			file.hadOriginal = true
		} else if !os.IsNotExist(err) {
			return withRollback(
				fmt.Errorf("impossible d'inspecter %s : %w", file.path, err),
				rollbackFiles(staged[:committed]),
			)
		}

		if err := os.Rename(file.tempPath, file.path); err != nil {
			var restoreErr error
			if file.hadOriginal {
				restoreErr = os.Rename(file.backupPath, file.path)
			}
			rollbackErr := rollbackFiles(staged[:committed])
			if restoreErr != nil {
				rollbackErr = fmt.Errorf(
					"restauration de %s impossible : %v ; rollback precedent : %v",
					file.path,
					restoreErr,
					rollbackErr,
				)
			}
			return withRollback(
				fmt.Errorf("impossible de remplacer %s : %w", file.path, err),
				rollbackErr,
			)
		}
		committed++
	}

	commitSucceeded = true
	return nil
}

func rollbackFiles(files []TransactionFile) error {
	var rollbackErr error
	for index := len(files) - 1; index >= 0; index-- {
		file := files[index]
		if err := os.Remove(file.path); err != nil && !os.IsNotExist(err) {
			rollbackErr = fmt.Errorf("impossible de supprimer %s pendant le rollback : %w", file.path, err)
			continue
		}
		if file.hadOriginal {
			if err := os.Rename(file.backupPath, file.path); err != nil {
				rollbackErr = fmt.Errorf("impossible de restaurer %s : %w", file.path, err)
			}
		}
	}
	return rollbackErr
}

func withRollback(operationErr error, rollbackErr error) error {
	if rollbackErr == nil {
		return operationErr
	}
	return fmt.Errorf("%w ; rollback incomplet : %v", operationErr, rollbackErr)
}
