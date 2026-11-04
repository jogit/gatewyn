package caddyconf

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestShippedCodeDoesNotImportCaddy garde le programme léger : importer les types de Caddy ajoutait
// 36 Mo. Seuls les tests peuvent le faire (voir types_caddy_test.go).
func TestShippedCodeDoesNotImportCaddy(t *testing.T) {
	root := filepath.Join("..", "..")
	filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		if !strings.Contains(path, "internal") && !strings.Contains(path, "cmd") {
			return nil
		}
		b, _ := os.ReadFile(path)
		if strings.Contains(string(b), `"github.com/caddyserver/caddy`) {
			t.Errorf("%s importe Caddy : utiliser les structures de model.go", path)
		}
		return nil
	})
}
