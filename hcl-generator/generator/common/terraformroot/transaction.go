package terraformroot

import (
	"fmt"
	"os"
	"path/filepath"

	"hcl-generator/generator/common"
)

// CommitPreparedFiles cree les repertoires necessaires puis delegue l'ecriture
// a la transaction commune : fichiers temporaires, sauvegardes, renommages
// atomiques et rollback complet en cas d'echec.
func CommitPreparedFiles(prepared map[string][]byte) error {
	for path := range prepared {
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return fmt.Errorf(
				"impossible de creer le repertoire de %s : %w",
				path,
				err,
			)
		}
	}
	return common.CommitFilePathsAtomically(prepared)
}
